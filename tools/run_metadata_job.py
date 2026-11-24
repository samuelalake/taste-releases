"""Run one submitted private metadata job against the preview store only.

The job descriptor is age-decrypted in the runner; nothing in the outer request
carries a URL, host, path, or credential. The batch payload is fetched from
private R2 by hash name (`imports/source-files/<sha256>.json` — the existing
transfer prefix; there is no separate `metadata-jobs` prefix), its SHA-256 is
verified, and its own fingerprint is checked before any POST.

Authentication to the preview deployment is renewable, never a static secret:
the runner mints a fresh short-lived GitHub Actions OIDC token per run
(`id-token: write`) and sends it as `x-vercel-trusted-oidc-idp-token` under the
Vercel Trusted Sources rule for this repository. No `VERCEL_OIDC_TOKEN` is
provisioned, read, or accepted anywhere in this file.

Kinds: `import` posts a StoredBatch to POST /api/imports/stored;
`reconcile` posts a SameCaptureReconciliation to POST /api/imports/reconcile
(the guarded #34 route: owner session or import token, preview-only, exact
`reconciliationDigest`, response `{reconciliationId, applied,
bulkVariantsRecorded, flowsVerified, replay, audit}`).

Receipt replay is a re-validation, never a lookup: a stored receipt replays
only after the batch is re-fetched and hash/fingerprint-verified, the receipt's
preview origin is checked against the configured origin, and a fresh ordered
membership readback from the live preview store matches the receipt exactly.
The replay is bound to the sealed config: the job carries the config's
batchKey and batchSha256, the receipt's batchKey and batchSha256 must equal
them exactly, and the batch is re-fetched by the config-authorized key — a
receipt for a different batch can never replay. Any mismatch fails the job;
nothing is re-posted on a failed replay.
"""
import base64
import io
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from bundle import require, sha, unique_json
from run_request import decrypt_descriptor
from sealed_metadata_request import job_descriptor, parse_job_request
from transfer import BUCKET, immutable

# The guarded preview import route. Production has its own owner-reviewed exact-batch path and is
# never posted to from here.
IMPORT_PATH = "/api/imports/stored"
# The guarded preview reconciliation route (Taste PR #34). Same guards as the import route.
RECONCILE_PATH = "/api/imports/reconcile"
ARTIFACT_PATH = "/api/artifacts/"
MAX_BATCH_BYTES = 4_000_000  # the route rejects a larger content-length
MAX_RECONCILE_PAYLOAD_BYTES = 1_000_000  # the reconcile route rejects a larger content-length
MAX_RECEIPT_BYTES = 1_000_000  # receipts are a few kilobytes; anything larger is not a receipt
RECEIPT_PREFIX = "imports/metadata-job-receipts/"
BATCH_KEY = re.compile(r"^imports/source-files/[0-9a-f]{64}\.json$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("Redirect refused")


def canonical_digest(value):
    """Mirror src/lib/importStored.ts digestData: recursively sort object keys, compact JSON, SHA-256."""
    def canonical(v):
        if isinstance(v, list):
            return [canonical(x) for x in v]
        if isinstance(v, dict):
            return {k: canonical(v[k]) for k in sorted(v)}
        return v
    return sha(json.dumps(canonical(value), separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def preview_origin(raw):
    """The fixed owner-configured preview origin. Anything else is refused."""
    require(isinstance(raw, str) and raw)
    url = urllib.parse.urlsplit(raw)
    require(url.scheme == "https" and url.hostname and url.hostname.endswith(".vercel.app"))
    require(url.port in (None, 443) and not url.username and not url.password)
    require(not url.fragment and url.path in ("", "/") and not url.query)
    require(re.fullmatch(r"[a-z0-9.-]+\.vercel\.app", url.hostname))
    return "https://" + url.hostname


def r2_client(role, account):
    import boto3
    from botocore.config import Config
    return boto3.client("s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
                        region_name="auto",
                        aws_access_key_id=os.environ[f"TASTE_R2_{role}_ACCESS_KEY_ID"],
                        aws_secret_access_key=os.environ[f"TASTE_R2_{role}_SECRET_ACCESS_KEY"],
                        config=Config(signature_version="s3v4", retries={"mode": "standard", "max_attempts": 3},
                                      connect_timeout=15, read_timeout=60,
                                      request_checksum_calculation="when_required",
                                      response_checksum_validation="when_required"))


def payload_fingerprint(kind, payload):
    """The payload's own fingerprint (the id field excluded), checked against the
    id the payload carries. Import uses `batchDigest`; reconcile uses
    `reconciliationDigest` — both are the same canonical digestData algorithm."""
    require(isinstance(payload, dict))
    if kind == "import":
        require(set(payload) == {"batchId", "artifacts", "units", "flows", "objects"})
        rest = {k: v for k, v in payload.items() if k != "batchId"}
        require(canonical_digest(rest) == payload["batchId"])
        return payload["batchId"]
    if kind == "reconcile":
        require(set(payload) == {"reconciliationId", "artifactId", "captureId", "correction", "units", "flows"})
        rest = {k: v for k, v in payload.items() if k != "reconciliationId"}
        require(canonical_digest(rest) == payload["reconciliationId"])
        return payload["reconciliationId"]
    raise ValueError("Unknown job kind")


def fetch_batch(reader, key, expected_sha, max_bytes=MAX_BATCH_BYTES):
    """Fetch the immutable hash-named batch JSON from private R2 and verify its hash.
    The key is the existing `imports/source-files/` prefix; the read is bounded
    (import payloads at most 4,000,000 bytes, reconcile payloads at most 1,000,000)."""
    require(isinstance(key, str) and BATCH_KEY.fullmatch(key))
    response = reader.get_object(Bucket=BUCKET, Key=key)
    try:
        body = response["Body"].read(max_bytes + 1)
        require(len(body) <= max_bytes and sha(body) == expected_sha)
        require(response.get("ContentType") == "application/json")
    finally:
        response["Body"].close()
    return body


def preview_opener(origin, bearer, oidc_token):
    """An opener that only talks to the fixed preview origin, never follows redirects or proxies."""
    addresses = socket.getaddrinfo(urllib.parse.urlsplit(origin).hostname, 443, type=socket.SOCK_STREAM)
    require(addresses and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses))
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    opener.addheaders = [("Authorization", "Bearer " + bearer),
                         ("x-vercel-trusted-oidc-idp-token", oidc_token)]
    return opener


def mint_github_oidc_token(audience=None):
    """Mint a short-lived GitHub Actions OIDC token for this run.

    Uses the runner's own token endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL` /
    `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, available only when the workflow grants
    `id-token: write`). The token is minted fresh per run and re-minted shortly
    before expiry; no static Vercel bypass secret is stored, provisioned, or
    accepted anywhere in this file. Returns (token, expires_at_epoch). The JWT
    signature is verified by Vercel under the Trusted Sources rule; only `exp`
    is read here, to know when to re-mint."""
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    require(url and request_token)
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "https")
    require(parts.hostname is not None and parts.hostname.endswith(".actions.githubusercontent.com"))
    require(not parts.username and not parts.fragment)
    if audience:
        url = url + ("&" if parts.query else "?") + "audience=" + urllib.parse.quote(audience, safe="")
    request = urllib.request.Request(url, headers={"Authorization": "bearer " + request_token,
                                                  "Accept": "application/json"}, method="GET")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=30) as response:
            require(response.status == 200)
            body = response.read()
    except (urllib.error.URLError, urllib.error.HTTPError) as error:
        raise ValueError("OIDC token mint failed") from None
    require(len(body) <= 1_000_000)
    data = unique_json(body)
    require(isinstance(data, dict) and isinstance(data.get("value"), str) and data["value"])
    token = data["value"]
    segments = token.split(".")
    require(len(segments) == 3)
    try:
        padded = segments[1] + "=" * (-len(segments[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:
        raise ValueError("OIDC token is not a parseable JWT") from None
    exp = claims.get("exp")
    expires = int(exp) if isinstance(exp, int) else int(time.time())
    return token, expires


class OidcTokenCache:
    """One short-lived OIDC token per run, re-minted shortly before expiry."""

    REFRESH_BEFORE_SECONDS = 60

    def __init__(self, audience=None):
        self.audience = audience
        self.token = None
        self.expires = 0

    def get(self):
        now = int(time.time())
        if self.token is None or self.expires - now <= self.REFRESH_BEFORE_SECONDS:
            self.token, self.expires = mint_github_oidc_token(self.audience)
        return self.token


class PreviewSession:
    """A preview-store session: each request carries the bearer token and a
    freshly minted (or still-valid) OIDC token. The opener is built per request
    so an expiring token is re-minted before the next call."""

    def __init__(self, origin, bearer, oidc_cache):
        self.origin = origin
        self.bearer = bearer
        self.oidc_cache = oidc_cache

    def open(self, request, timeout=30):
        opener = preview_opener(self.origin, self.bearer, self.oidc_cache.get())
        return opener.open(request, timeout=timeout)


def http_json(opener, request, timeout):
    with opener.open(request, timeout=timeout) as response:
        return json.load(response)


def post_import(opener, origin, batch_bytes):
    """POST the batch to the guarded preview import route, retrying only transient failures."""
    request = urllib.request.Request(origin + IMPORT_PATH, data=batch_bytes,
                                     headers={"Content-Type": "application/json"}, method="POST")
    last = None
    for _attempt in range(3):
        try:
            return http_json(opener, request, timeout=320)
        except urllib.error.HTTPError as error:
            last = error
            if error.code not in (429, 500, 502, 503, 504):
                raise ValueError("Preview import refused") from None
            time.sleep(2)
    raise ValueError("Preview import refused") from last


def post_reconcile(opener, origin, payload_bytes):
    """POST the reconciliation to the guarded preview reconcile route (#34),
    retrying only transient failures."""
    request = urllib.request.Request(origin + RECONCILE_PATH, data=payload_bytes,
                                     headers={"Content-Type": "application/json"}, method="POST")
    last = None
    for _attempt in range(3):
        try:
            return http_json(opener, request, timeout=320)
        except urllib.error.HTTPError as error:
            last = error
            if error.code not in (429, 500, 502, 503, 504):
                raise ValueError("Preview reconciliation refused") from None
            time.sleep(2)
    raise ValueError("Preview reconciliation refused") from last


def verify_memberships(opener, origin, batch):
    """Verify ALL expected flow memberships via the artifact endpoint, plus the import audit."""
    audit = http_json(opener, urllib.request.Request(origin + IMPORT_PATH, method="GET"), timeout=60)
    require(audit.get("allFlowMembersResolve") is True)
    verified = []
    for artifact in batch["artifacts"]:
        got = http_json(opener, urllib.request.Request(origin + ARTIFACT_PATH + artifact["id"], method="GET"), timeout=60)
        expected_units = sorted(((u["id"], u["order"]) for u in batch["units"] if u["artifactId"] == artifact["id"]),
                                key=lambda pair: pair[1])
        seen_units = sorted(((u["id"], u["order"]) for u in got["units"]), key=lambda pair: pair[1])
        require(seen_units == expected_units)
        expected_flows = {f["id"]: [(v["unitId"], v["order"]) for v in f["members"]]
                          for f in batch["flows"] if f["artifactId"] == artifact["id"]}
        seen_flows = {f["id"]: [(v["unitId"], v["order"]) for v in f["members"]] for f in got["flows"]}
        require(seen_flows == expected_flows)
        verified.append({"artifactId": artifact["id"], "units": len(expected_units),
                         "flows": len(expected_flows), "ok": True})
    return audit, verified


def verify_reconciliation_memberships(opener, origin, payload):
    """Fresh ordered readback for a reconciliation: every moved unit sits at its
    target order, and every verified flow matches name, source URL and member
    sequence exactly. Only the payload's units and flows are checked — the
    artifact already holds other units from the earlier partial import. The
    route already validated these before mutating; this is the runner's
    independent readback from the live preview store."""
    got = http_json(opener, urllib.request.Request(origin + ARTIFACT_PATH + payload["artifactId"], method="GET"), timeout=60)
    require(isinstance(got, dict))
    require(isinstance(got.get("units"), list) and isinstance(got.get("flows"), list))
    units = {u["id"]: u for u in got["units"] if isinstance(u, dict) and "id" in u}
    flows = {f["id"]: f for f in got["flows"] if isinstance(f, dict) and "id" in f}
    for unit in payload["units"]:
        found = units.get(unit["unitId"])
        require(found is not None and found.get("order") == unit["toOrder"])
    for flow in payload["flows"]:
        found = flows.get(flow["flowId"])
        require(found is not None)
        if "name" in found:
            require(found["name"] == flow["name"])
        if "sourceUrl" in found:
            require(found["sourceUrl"] == flow["sourceUrl"])
        require(isinstance(found.get("members"), list))
        require([(m["unitId"], m["order"]) for m in found["members"]] ==
                [(m["unitId"], m["order"]) for m in flow["members"]])
    return [{"artifactId": payload["artifactId"], "units": len(payload["units"]),
             "flows": len(payload["flows"]), "ok": True}]


def verify_reconciliation(opener, origin, payload, result):
    """Check the #34 reconcile response, then read back every moved unit and
    verified flow from the live preview store. Accepts both a first apply and a
    route-level replay (applied 0, replay true) — the readback is what proves
    the end state either way."""
    require(isinstance(result, dict))
    require(result.get("reconciliationId") == payload["reconciliationId"])
    require(isinstance(result.get("applied"), int) and isinstance(result.get("bulkVariantsRecorded"), int))
    require(isinstance(result.get("flowsVerified"), int) and result["flowsVerified"] == len(payload["flows"]))
    require(isinstance(result.get("replay"), bool))
    if result["replay"]:
        require(result["applied"] == 0 and result["bulkVariantsRecorded"] == 0)
    else:
        require(result["applied"] == len(payload["units"]))
        require(result["bulkVariantsRecorded"] == len(payload["units"]))
    audit_after = result.get("audit")
    require(isinstance(audit_after, dict) and audit_after.get("allFlowMembersResolve") is True)
    return verify_reconciliation_memberships(opener, origin, payload)


def read_receipt(reader, key):
    """Bounded private receipt read: at most 1,000,000 bytes, strict JSON with
    no duplicate keys, from the private R2 receipt prefix only. Returns None
    when absent; any other read failure (or an oversize receipt) is fatal,
    never treated as 'no receipt'."""
    try:
        response = reader.get_object(Bucket=BUCKET, Key=key)
    except Exception as error:
        if getattr(error, "response", {}).get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return None
        raise
    try:
        data = response["Body"].read(MAX_RECEIPT_BYTES + 1)
        require(len(data) <= MAX_RECEIPT_BYTES)
        return unique_json(data)
    finally:
        response["Body"].close()


def validate_receipt(receipt, job):
    """Strict receipt schema: exact keys per kind, hex formats, internal
    consistency. The receipt is never trusted on shape alone — validate_replay
    re-checks it against the re-fetched batch and the live preview store."""
    require(isinstance(receipt, dict))
    kind = job["kind"]
    common = {"version", "kind", "jobId", "jobSha256", "batchKey", "batchSha256",
              "previewOrigin", "previewOriginSha256", "auditBefore", "auditAfter",
              "membershipVerification", "verifiedAt"}
    if kind == "import":
        require(set(receipt) == common | {"batchId", "created", "exists", "replay"})
        require(isinstance(receipt["batchId"], str) and HEX64.fullmatch(receipt["batchId"]))
        require(isinstance(receipt["created"], int) and isinstance(receipt["exists"], int))
    elif kind == "reconcile":
        require(set(receipt) == common | {"reconciliationId", "applied", "bulkVariantsRecorded", "flowsVerified", "replay"})
        require(isinstance(receipt["reconciliationId"], str) and HEX64.fullmatch(receipt["reconciliationId"]))
        require(isinstance(receipt["applied"], int) and isinstance(receipt["bulkVariantsRecorded"], int))
        require(isinstance(receipt["flowsVerified"], int))
    else:
        raise ValueError("Unknown job kind")
    require(receipt["version"] == 1 and receipt["kind"] == kind)
    require(isinstance(receipt["jobId"], str) and HEX32.fullmatch(receipt["jobId"]))
    require(receipt["jobId"] == job["jobId"])
    require(isinstance(receipt["jobSha256"], str) and HEX64.fullmatch(receipt["jobSha256"]))
    require(receipt["jobSha256"] == job["jobSha256"])
    require(isinstance(receipt["batchKey"], str) and BATCH_KEY.fullmatch(receipt["batchKey"]))
    require(isinstance(receipt["batchSha256"], str) and HEX64.fullmatch(receipt["batchSha256"]))
    require(receipt["batchSha256"] == receipt["batchKey"].split("/")[-1].split(".")[0])
    # Replay binding: the receipt must name exactly the batch the sealed config
    # authorized. The job carries the config's batchKey/batchSha256 (main());
    # a receipt for any other batch is refused here, before any fetch or
    # readback. Without this, a valid receipt for batch A would replay under a
    # config authorizing batch B.
    require(receipt["batchKey"] == job["batchKey"])
    require(receipt["batchSha256"] == job["batchSha256"])
    require(isinstance(receipt["previewOrigin"], str) and receipt["previewOrigin"])
    require(isinstance(receipt["previewOriginSha256"], str) and HEX64.fullmatch(receipt["previewOriginSha256"]))
    require(sha(receipt["previewOrigin"].encode()) == receipt["previewOriginSha256"])
    require(isinstance(receipt["replay"], bool))
    for audit_key in ("auditBefore", "auditAfter"):
        audit_value = receipt[audit_key]
        require(isinstance(audit_value, dict) and set(audit_value) == {"artifacts", "units", "flows"})
        require(all(isinstance(audit_value[k], int) for k in ("artifacts", "units", "flows")))
    require(isinstance(receipt["membershipVerification"], list))
    for entry in receipt["membershipVerification"]:
        require(isinstance(entry, dict))
        require(set(entry) == {"artifactId", "units", "flows", "ok"})
        require(isinstance(entry["units"], int) and isinstance(entry["flows"], int))
        require(entry["ok"] is True)
    require(isinstance(receipt["verifiedAt"], str) and receipt["verifiedAt"])


def validate_replay(job, receipt, opener, origin, reader):
    """Re-validate a stored receipt from scratch. Returns the receipt when
    every check passes; raises on any mismatch. A receipt that cannot be
    re-validated never replays — the job fails and a fresh job must be sealed.
    Checks, in order: receipt schema (including exact batch equality against
    the sealed config's batchKey/batchSha256), preview origin (the receipt's
    origin and its hash must equal the configured origin), batch re-fetch by
    the config-authorized key with SHA-256 and fingerprint, live audit (all
    flow members resolve), and a fresh ordered membership readback that must
    equal the receipt's verification exactly."""
    validate_receipt(receipt, job)
    require(receipt["previewOrigin"] == origin)
    require(receipt["previewOriginSha256"] == sha(origin.encode()))
    kind = job["kind"]
    max_bytes = MAX_RECONCILE_PAYLOAD_BYTES if kind == "reconcile" else MAX_BATCH_BYTES
    # The re-fetch is bound to the config-authorized batch identity, never to
    # the receipt's fields: even a receipt that passed schema could not steer
    # the replay to a different batch.
    batch_bytes = fetch_batch(reader, job["batchKey"], job["batchSha256"], max_bytes)
    payload = unique_json(batch_bytes)
    fingerprint = payload_fingerprint(kind, payload)
    if kind == "import":
        require(fingerprint == receipt["batchId"])
        audit_after, fresh = verify_memberships(opener, origin, payload)
    else:
        require(fingerprint == receipt["reconciliationId"])
        audit_after = http_json(opener, urllib.request.Request(origin + IMPORT_PATH, method="GET"), timeout=60)
        require(audit_after.get("allFlowMembersResolve") is True)
        fresh = verify_reconciliation_memberships(opener, origin, payload)
    require(fresh == receipt["membershipVerification"])
    return receipt


def main():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    request, sealed = parse_job_request(event["inputs"]["request"])
    origin = preview_origin(os.environ["TASTE_PREVIEW_ORIGIN"])
    with tempfile.TemporaryDirectory(prefix="taste-metadata-job-", dir=os.environ["RUNNER_TEMP"]) as temp:
        raw = decrypt_descriptor(sealed, os.environ["TASTE_AGE_IDENTITY"], os.environ["TASTE_AGE_RECIPIENT"],
                                 Path(os.environ["RUNNER_TEMP"]) / "taste-age", Path(temp))
        require(len(raw.encode()) <= 4096)
        config = job_descriptor(raw)
        require(config["jobId"] == request["jobId"])
        kind = config["kind"]
        account = os.environ["TASTE_R2_ACCOUNT_ID"]
        require(re.fullmatch("[0-9a-f]{32}", account))
        reader = r2_client("READER", account)
        writer = r2_client("WRITER", account)
        receipt_key = RECEIPT_PREFIX + request["jobSha256"] + ".json"
        # The job carries the sealed config's batch identity: replay is bound
        # to exactly the batch the config authorized (see validate_receipt /
        # validate_replay). The jobId/jobSha256/kind alone do not identify a
        # batch, and the receipt's batch fields are never trusted on their own.
        job = {"jobId": request["jobId"], "jobSha256": request["jobSha256"], "kind": kind,
               "batchKey": config["batchKey"], "batchSha256": config["batchSha256"]}
        # Renewable preview auth: a short-lived GitHub OIDC token, minted per run
        # (and re-minted shortly before expiry). No static VERCEL_OIDC_TOKEN is
        # read or accepted anywhere in this file.
        oidc_cache = OidcTokenCache(os.environ.get("VERCEL_OIDC_AUDIENCE") or None)
        import_session = PreviewSession(origin, os.environ["TASTE_IMPORT_TOKEN"], oidc_cache)
        read_session = PreviewSession(origin, os.environ["TASTE_AGENT_TOKEN"], oidc_cache)
        # Replay: re-validate the stored receipt from scratch. A receipt that
        # cannot be re-validated fails the job; nothing is re-posted.
        existing = read_receipt(reader, receipt_key)
        if existing is not None:
            receipt = validate_replay(job, existing, read_session, origin, reader)
            print(json.dumps({"jobId": request["jobId"], "jobSha256": request["jobSha256"],
                              "kind": kind, "replay": True,
                              "verifiedAt": receipt["verifiedAt"]}, sort_keys=True))
            return
        max_bytes = MAX_RECONCILE_PAYLOAD_BYTES if kind == "reconcile" else MAX_BATCH_BYTES
        audit_before = http_json(read_session, urllib.request.Request(origin + IMPORT_PATH, method="GET"), timeout=60)
        batch_bytes = fetch_batch(reader, config["batchKey"], config["batchSha256"], max_bytes)
        payload = unique_json(batch_bytes)
        fingerprint = payload_fingerprint(kind, payload)
        if kind == "import":
            result = post_import(import_session, origin, batch_bytes)
            require(result.get("batchId") == payload["batchId"])
            audit_after, verified = verify_memberships(read_session, origin, payload)
            require(audit_after.get("units") == audit_before.get("units") + result.get("created", 0))
            require(audit_after.get("allFlowMembersResolve") is True)
            receipt = {"version": 1, "kind": "import", "jobId": request["jobId"],
                       "jobSha256": request["jobSha256"], "batchKey": config["batchKey"],
                       "batchSha256": config["batchSha256"], "previewOrigin": origin,
                       "previewOriginSha256": sha(origin.encode()),
                       "batchId": payload["batchId"], "created": result.get("created"),
                       "exists": result.get("exists"), "replay": result.get("replay", False),
                       "auditBefore": {k: audit_before.get(k) for k in ("artifacts", "units", "flows")},
                       "auditAfter": {k: audit_after.get(k) for k in ("artifacts", "units", "flows")},
                       "membershipVerification": verified,
                       "verifiedAt": datetime.now(timezone.utc).isoformat()}
            outcome = {"jobId": request["jobId"], "jobSha256": request["jobSha256"], "kind": "import",
                       "batchId": payload["batchId"], "created": result.get("created"),
                       "exists": result.get("exists"), "replay": result.get("replay", False),
                       "flowsVerified": sum(v["flows"] for v in verified)}
        else:
            result = post_reconcile(import_session, origin, batch_bytes)
            verified = verify_reconciliation(read_session, origin, payload, result)
            audit_after = result["audit"]
            receipt = {"version": 1, "kind": "reconcile", "jobId": request["jobId"],
                       "jobSha256": request["jobSha256"], "batchKey": config["batchKey"],
                       "batchSha256": config["batchSha256"], "previewOrigin": origin,
                       "previewOriginSha256": sha(origin.encode()),
                       "reconciliationId": payload["reconciliationId"],
                       "applied": result["applied"],
                       "bulkVariantsRecorded": result["bulkVariantsRecorded"],
                       "flowsVerified": result["flowsVerified"], "replay": result["replay"],
                       "auditBefore": {k: audit_before.get(k) for k in ("artifacts", "units", "flows")},
                       "auditAfter": {k: audit_after.get(k) for k in ("artifacts", "units", "flows")},
                       "membershipVerification": verified,
                       "verifiedAt": datetime.now(timezone.utc).isoformat()}
            outcome = {"jobId": request["jobId"], "jobSha256": request["jobSha256"], "kind": "reconcile",
                       "reconciliationId": payload["reconciliationId"],
                       "applied": result["applied"],
                       "bulkVariantsRecorded": result["bulkVariantsRecorded"],
                       "flowsVerified": result["flowsVerified"], "replay": result["replay"]}
        receipt_bytes = json.dumps(receipt, sort_keys=True).encode()
        immutable(writer, reader, receipt_key, receipt_bytes, "application/json")
        print(json.dumps(outcome, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except Exception:
        print("Metadata job failed; no completion claimed; rerun verifies existing objects")
        raise SystemExit(1)
