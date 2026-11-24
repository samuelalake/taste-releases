import base64
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from sealed_metadata_request import job_descriptor, pack_job_request, parse_job_request
from run_metadata_job import canonical_digest, main, mint_github_oidc_token, OidcTokenCache
from bundle import sha

ORIGIN = "https://taste-abc123-sams-projects-67b5023f.vercel.app"


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Dict-backed S3 stand-in: immutable puts, hash-checked reads."""

    def __init__(self):
        self.objects = {}
        self.get_calls = []

    def get_object(self, Bucket, Key):
        self.get_calls.append(Key)
        if Key not in self.objects:
            raise FakeClientError("NoSuchKey")
        payload, content_type = self.objects[Key]
        return {"ContentLength": len(payload), "ContentType": content_type,
                "Metadata": {"sha256": sha(payload)}, "Body": io.BytesIO(payload)}

    def put_object(self, Bucket, Key, Body, ContentLength, ContentType, Metadata=None, IfNoneMatch=None):
        if IfNoneMatch == "*" and Key in self.objects:
            raise FakeClientError("PreconditionFailed")
        data = Body if isinstance(Body, bytes) else Body.read()
        self.objects[Key] = (data, ContentType)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Records requests; answers canned preview JSON per (method, path).

    `reconcile` is a SameCaptureReconciliation payload the preview store is
    taken to hold: POSTs to the reconcile route return its applied result and
    artifact GETs return its units at their target orders with its flows
    exact. `reconcile_view` optionally overrides what the artifact GET returns
    (a changed membership the runner must refuse on readback)."""

    def __init__(self, bearer, batch, audit_before, audit_after, reconcile=None,
                 reconcile_view=None):
        self.bearer = bearer
        self.batch = batch
        self.audit_before = audit_before
        self.audit_after = audit_after
        self.reconcile = reconcile
        self.reconcile_view = reconcile_view if reconcile_view is not None else reconcile
        self.posts = []
        self.gets = []
        self.audit_calls = 0

    def open(self, request, timeout=None):
        url = request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        if request.get_method() == "POST":
            self.posts.append((url, headers))
            if url.endswith("/api/imports/reconcile") and self.reconcile is not None:
                payload = self.reconcile
                return FakeResponse(json.dumps({
                    "reconciliationId": payload["reconciliationId"],
                    "applied": len(payload["units"]),
                    "bulkVariantsRecorded": len(payload["units"]),
                    "flowsVerified": len(payload["flows"]),
                    "replay": False, "audit": self.audit_after}).encode())
            return FakeResponse(json.dumps(
                {"batchId": self.batch["batchId"], "created": 2, "exists": 0, "replay": False}).encode())
        self.gets.append((url, headers))
        if url.endswith("/api/imports/stored"):
            self.audit_calls += 1
            audit = self.audit_before if self.audit_calls == 1 else self.audit_after
            return FakeResponse(json.dumps(audit).encode())
        artifact_id = url.rsplit("/api/artifacts/", 1)[-1]
        if self.reconcile_view is not None:
            units = [{"id": u["unitId"], "order": u["toOrder"]}
                     for u in self.reconcile_view["units"]]
            flows = [{"id": f["flowId"], "name": f["name"], "sourceUrl": f["sourceUrl"],
                      "members": f["members"]} for f in self.reconcile_view["flows"]]
            return FakeResponse(json.dumps({"id": artifact_id, "units": units, "flows": flows}).encode())
        units = [{"id": u["id"], "order": u["order"]} for u in self.batch["units"]
                  if u["artifactId"] == artifact_id]
        flows = [{"id": f["id"], "members": f["members"]} for f in self.batch["flows"]
                 if f["artifactId"] == artifact_id]
        return FakeResponse(json.dumps({"id": artifact_id, "units": units, "flows": flows}).encode())


def make_batch():
    envelope = "imports/source-files/" + "a" * 64 + ".json"
    image = "images/imported/" + "b" * 64 + ".png"
    provenance = {"sourceId": "test-app-id", "envelopeKey": envelope, "captures": []}
    payload = {
        "artifacts": [{"id": "mobbin-app-test", "name": "Test", "medium": "Mobile app",
                       "platform": "ios", "provenance": provenance}],
        "units": [
            {"id": "mobbin-u1", "artifactId": "mobbin-app-test", "order": 1, "unit": "Screen",
             "title": "Test 1", "source": "Mobbin",
             "sourceUrl": "https://mobbin.com/screens/11111111-1111-4111-8111-111111111111",
             "collections": ["Trove references"], "provenance": provenance,
             "image": {"path": image, "contentType": "image/png", "width": 1179, "height": 2676}},
            {"id": "mobbin-u2", "artifactId": "mobbin-app-test", "order": 2, "unit": "Screen",
             "title": "Test 2", "source": "Mobbin",
             "sourceUrl": "https://mobbin.com/screens/22222222-2222-4222-8222-222222222222",
             "collections": ["Trove references"], "provenance": provenance,
             "image": {"path": image, "contentType": "image/png", "width": 1179, "height": 2676}},
        ],
        "flows": [{"id": "flow-test", "name": "Test flow", "artifactId": "mobbin-app-test",
                   "sourceUrl": "https://mobbin.com/flows/33333333-3333-4333-8333-333333333333",
                   "members": [{"unitId": "mobbin-u1", "order": 1}, {"unitId": "mobbin-u2", "order": 2}]}],
        "objects": [
            {"key": image, "bytes": 100, "sha256": "b" * 64, "contentType": "image/png"},
            {"key": envelope, "bytes": 50, "sha256": "a" * 64, "contentType": "application/json"},
        ],
    }
    return {"batchId": canonical_digest(payload), **payload}


def make_reconciliation():
    """A #34-style SameCaptureReconciliation payload, fingerprinted by
    reconciliationDigest (the same canonical digest as batchDigest)."""
    payload = {
        "artifactId": "mobbin-app-test",
        "captureId": "95760507-3617-4e64-9542-23e8a1c3286f",
        "correction": {
            "envelopeKey": "imports/source-files/" + "a" * 64 + ".json",
            "sha256": "a" * 64,
            "batchProvenanceKeys": ["imports/source-files/" + "b" * 64 + ".json"],
        },
        "units": [
            {"unitId": "mobbin-u1", "sourceId": "11111111-1111-4111-8111-111111111111",
             "sourceUrl": "https://mobbin.com/screens/11111111-1111-4111-8111-111111111111",
             "fromOrder": 1, "toOrder": 51,
             "canonicalImageKey": "images/imported/" + "c" * 64 + ".png",
             "bulkImageKey": "images/imported/" + "d" * 64 + ".png",
             "width": 1179, "height": 2676},
            {"unitId": "mobbin-u2", "sourceId": "22222222-2222-4222-8222-222222222222",
             "sourceUrl": "https://mobbin.com/screens/22222222-2222-4222-8222-222222222222",
             "fromOrder": 2, "toOrder": 52,
             "canonicalImageKey": "images/imported/" + "c" * 64 + ".png",
             "bulkImageKey": "images/imported/" + "d" * 64 + ".png",
             "width": 1179, "height": 2676},
        ],
        "flows": [{"flowId": "mobbin-flow-test", "name": "Logging food",
                   "sourceUrl": "https://mobbin.com/flows/33333333-3333-4333-8333-333333333333",
                   "members": [{"unitId": "mobbin-u1", "order": 1},
                               {"unitId": "mobbin-u2", "order": 2}]}],
    }
    return {"reconciliationId": canonical_digest(payload), **payload}


class MetadataJobTests(unittest.TestCase):
    def setUp(self):
        self.batch = make_batch()
        self.batch_bytes = json.dumps(self.batch, separators=(",", ":")).encode()
        self.batch_sha = sha(self.batch_bytes)
        self.batch_key = "imports/source-files/" + self.batch_sha + ".json"
        self.job_id = self.batch_sha[:32]
        self.descriptor = {"version": 1, "kind": "import", "jobId": self.job_id,
                           "batchKey": self.batch_key, "batchSha256": self.batch_sha,
                           "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                           "preview": True}
        self.reconciliation = make_reconciliation()
        self.reconciliation_bytes = json.dumps(self.reconciliation, separators=(",", ":")).encode()
        self.reconciliation_sha = sha(self.reconciliation_bytes)
        self.reconciliation_key = "imports/source-files/" + self.reconciliation_sha + ".json"
        self.reconciliation_job_id = self.reconciliation_sha[:32]
        self.reconciliation_descriptor = {"version": 1, "kind": "reconcile",
                                          "jobId": self.reconciliation_job_id,
                                          "batchKey": self.reconciliation_key,
                                          "batchSha256": self.reconciliation_sha,
                                          "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                                          "preview": True}
        # The OIDC token is minted per run in production; tests stand in a fixed
        # fake token so the mint itself is never exercised here.
        self.mint_patcher = patch("run_metadata_job.mint_github_oidc_token",
                                  return_value=("fake-oidc", 4102444800))
        self.mint_patcher.start()
        self.addCleanup(self.mint_patcher.stop)
        self.sealed = b"age-encryption.org/v1\n" + b"x" * 150
        self.body = pack_job_request(self.job_id, self.sealed)
        self.audit_before = {"artifacts": 5, "units": 10, "flows": 1, "allFlowMembersResolve": True}
        self.audit_after = {"artifacts": 6, "units": 12, "flows": 2, "allFlowMembersResolve": True}

    def event_env(self, temp, request_body=None):
        event = Path(temp) / "event.json"
        event.write_text(json.dumps({"inputs": {"request": request_body or self.body}}))
        return {"GITHUB_EVENT_PATH": str(event), "RUNNER_TEMP": temp,
                "TASTE_AGE_IDENTITY": "synthetic", "TASTE_AGE_RECIPIENT": "synthetic",
                "TASTE_PREVIEW_ORIGIN": ORIGIN, "TASTE_R2_ACCOUNT_ID": "a" * 32,
                "TASTE_IMPORT_TOKEN": "import-token", "TASTE_AGENT_TOKEN": "agent-token",
                # A static bypass token, if one were ever set: the runner must
                # never read or send it — the minted OIDC token is used instead.
                "VERCEL_OIDC_TOKEN": "static-sentinel-never-used"}

    def test_valid_bounded_request(self):
        request, sealed = parse_job_request(self.body)
        self.assertEqual(request["jobId"], self.job_id)
        self.assertEqual(sealed, self.sealed)

    def test_no_plaintext_or_extra_fields(self):
        for body in ("https://files.example.com/private", "[]", "{}"):
            with self.subTest(body=body), self.assertRaises((ValueError, json.JSONDecodeError)):
                parse_job_request(body)
        for extra in ({"bundleUrl": "https://files.example.com/private"},
                      {"host": "evil.example.com"}, {"path": "/api/imports/stored"},
                      {"target": "production"}, {"preview": False}):
            data = json.loads(self.body)
            data.update(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                parse_job_request(json.dumps(data))

    def test_tampered_hash_size_and_encoding(self):
        for changes in ({"jobSha256": "0" * 64}, {"sealedJob": "!"},
                        {"sealedJob": base64.b64encode(b"plain text").decode()},
                        {"jobId": "../../secret"}, {"version": True}):
            data = json.loads(self.body)
            data.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_job_request(json.dumps(data))
        with self.assertRaises(ValueError):
            pack_job_request(self.job_id, self.sealed * 100)
        with self.assertRaises(ValueError):
            parse_job_request(" " * 17000)

    def test_job_descriptor_rejects(self):
        good = dict(self.descriptor)
        bad = [
            {**good, "batchKey": "imports/metadata-jobs/" + self.batch_sha + ".json"},
            {**good, "batchKey": "https://files.example.com/" + self.batch_sha + ".json"},
            {**good, "batchKey": "imports/metadata-jobs/" + "0" * 64 + ".json"},
            {**good, "batchSha256": "0" * 64},
            {**good, "preview": False},
            {**good, "target": "production"},
            {**good, "kind": "publish"},
            {**good, "jobId": "g" * 32},
            {**good, "expiresAt": "2020-01-01T00:00:00Z"},
            {**good, "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=25)).isoformat()},
        ]
        for desc in bad:
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                job_descriptor(json.dumps(desc))
        self.assertEqual(job_descriptor(json.dumps(good))["jobId"], self.job_id)

    def test_job_descriptor_accepts_source_files_key(self):
        # Review note 1: batch payloads ride the existing source-files prefix.
        good = dict(self.descriptor)
        self.assertEqual(job_descriptor(json.dumps(good))["batchKey"], self.batch_key)

    def test_canonical_digest_is_key_order_stable_and_value_sensitive(self):
        a = {"b": 1, "a": {"d": [3, 2], "c": "x"}}
        b = {"a": {"c": "x", "d": [3, 2]}, "b": 1}
        self.assertEqual(canonical_digest(a), canonical_digest(b))
        self.assertNotEqual(canonical_digest(a), canonical_digest({"b": 2, "a": {"d": [3, 2], "c": "x"}}))
        self.assertNotEqual(canonical_digest(a), canonical_digest({"b": 1, "a": {"d": [2, 3], "c": "x"}}))
        self.assertEqual(len(canonical_digest(a)), 64)

    def test_production_targeting_never_reaches_post(self):
        desc = dict(self.descriptor, preview=False)
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(desc)), \
                 patch("run_metadata_job.r2_client") as clients, \
                 patch("run_metadata_job.preview_opener") as opener:
                with self.assertRaises(ValueError):
                    main()
                clients.assert_not_called()
                opener.assert_not_called()

    def test_wrong_origin_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            env["TASTE_PREVIEW_ORIGIN"] = "https://evil.example.com/"
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.descriptor)), \
                 patch("run_metadata_job.r2_client") as clients:
                with self.assertRaises(ValueError):
                    main()
                clients.assert_not_called()

    def test_expired_or_changed_batch_never_reaches_post(self):
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            fake_s3 = FakeS3()
            fake_s3.objects[self.batch_key] = (b"tampered bytes", "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before, self.audit_after)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    main()
                self.assertEqual(opener.posts, [])

    def reconcile_body(self, descriptor):
        return pack_job_request(descriptor["jobId"], self.sealed)

    def test_reconcile_flow_with_mocks(self):
        # Review note: kind:"reconcile" is wired to the #34 route
        # (POST /api/imports/reconcile) — its contract was verified against the
        # route at head 3ec69af: preview-only, exact reconciliationDigest,
        # response {reconciliationId, applied, bulkVariantsRecorded,
        # flowsVerified, replay, audit}.
        sealed_body = self.reconcile_body(self.reconciliation_descriptor)
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=sealed_body)
            fake_s3 = FakeS3()
            fake_s3.objects[self.reconciliation_key] = (self.reconciliation_bytes, "application/json")
            openers = {}

            def make_opener(origin, bearer, oidc):
                if bearer not in openers:
                    openers[bearer] = FakeOpener(bearer, self.batch, self.audit_before,
                                                 self.audit_after, reconcile=self.reconciliation)
                return openers[bearer]

            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.reconciliation_descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", side_effect=make_opener):
                main()
            import_opener = openers["import-token"]
            read_opener = openers["agent-token"]
            self.assertEqual(len(import_opener.posts), 1)
            self.assertTrue(import_opener.posts[0][0].endswith("/api/imports/reconcile"))
            self.assertEqual(len(read_opener.posts), 0)
            self.assertTrue(any(u.endswith("/api/artifacts/mobbin-app-test") for u, _ in read_opener.gets))
            receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
            self.assertIn(receipt_key, fake_s3.objects)
            receipt = json.loads(fake_s3.objects[receipt_key][0])
            self.assertEqual(receipt["kind"], "reconcile")
            self.assertEqual(receipt["reconciliationId"], self.reconciliation["reconciliationId"])
            self.assertEqual(receipt["applied"], 2)
            self.assertEqual(receipt["bulkVariantsRecorded"], 2)
            self.assertEqual(receipt["flowsVerified"], 1)
            self.assertEqual(receipt["membershipVerification"],
                             [{"artifactId": "mobbin-app-test", "units": 2, "flows": 1, "ok": True}])

    def test_reconcile_fingerprint_mismatch_never_reaches_post(self):
        tampered = dict(self.reconciliation)
        tampered["reconciliationId"] = "0" * 64
        tampered_bytes = json.dumps(tampered, separators=(",", ":")).encode()
        tampered_sha = sha(tampered_bytes)
        tampered_key = "imports/source-files/" + tampered_sha + ".json"
        desc = dict(self.reconciliation_descriptor, batchKey=tampered_key,
                    batchSha256=tampered_sha, jobId=tampered_sha[:32])
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=self.reconcile_body(desc))
            fake_s3 = FakeS3()
            fake_s3.objects[tampered_key] = (tampered_bytes, "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before,
                                self.audit_after, reconcile=self.reconciliation)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(desc)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    main()
                self.assertEqual(opener.posts, [])

    def test_reconcile_response_mismatch_refused(self):
        wrong = dict(self.reconciliation, reconciliationId="1" * 64)
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=self.reconcile_body(self.reconciliation_descriptor))
            fake_s3 = FakeS3()
            fake_s3.objects[self.reconciliation_key] = (self.reconciliation_bytes, "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before,
                                self.audit_after, reconcile=wrong)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.reconciliation_descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    main()
                receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
                self.assertNotIn(receipt_key, fake_s3.objects)

    def test_reconcile_payload_too_large_refused(self):
        padded = self.reconciliation_bytes + b" " * (1_000_001 - len(self.reconciliation_bytes))
        padded_sha = sha(padded)
        padded_key = "imports/source-files/" + padded_sha + ".json"
        desc = dict(self.reconciliation_descriptor, batchKey=padded_key,
                    batchSha256=padded_sha, jobId=padded_sha[:32])
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=self.reconcile_body(desc))
            fake_s3 = FakeS3()
            fake_s3.objects[padded_key] = (padded, "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before,
                                self.audit_after, reconcile=self.reconciliation)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(desc)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    main()
                self.assertEqual(opener.posts, [])

    def test_import_flow_with_mocks(self):
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            fake_s3 = FakeS3()
            fake_s3.objects[self.batch_key] = (self.batch_bytes, "application/json")
            openers = {}

            def make_opener(origin, bearer, oidc):
                # The session mints a fresh OIDC token per run; the static
                # sentinel in the environment must never be sent.
                self.assertEqual(oidc, "fake-oidc")
                self.assertNotEqual(oidc, "static-sentinel-never-used")
                if bearer not in openers:
                    openers[bearer] = FakeOpener(bearer, self.batch, self.audit_before, self.audit_after)
                return openers[bearer]

            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", side_effect=make_opener):
                main()
            import_opener = openers["import-token"]
            read_opener = openers["agent-token"]
            self.assertEqual(len(import_opener.posts), 1)
            self.assertTrue(import_opener.posts[0][0].endswith("/api/imports/stored"))
            self.assertEqual(len(read_opener.posts), 0)
            self.assertTrue(any(u.endswith("/api/artifacts/mobbin-app-test") for u, _ in read_opener.gets))
            receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
            self.assertIn(receipt_key, fake_s3.objects)
            receipt = json.loads(fake_s3.objects[receipt_key][0])
            self.assertEqual(receipt["jobId"], self.job_id)
            self.assertEqual(receipt["batchSha256"], self.batch_sha)
            self.assertEqual(receipt["previewOrigin"], ORIGIN)
            self.assertEqual(receipt["created"], 2)
            self.assertEqual(receipt["membershipVerification"],
                             [{"artifactId": "mobbin-app-test", "units": 2, "flows": 1, "ok": True}])

    def valid_receipt(self):
        return {"version": 1, "kind": "import", "jobId": self.job_id,
                "jobSha256": hashlib.sha256(self.sealed).hexdigest(),
                "batchKey": self.batch_key, "batchSha256": self.batch_sha,
                "previewOrigin": ORIGIN, "previewOriginSha256": sha(ORIGIN.encode()),
                "batchId": self.batch["batchId"], "created": 2, "exists": 0, "replay": False,
                "auditBefore": {"artifacts": 5, "units": 10, "flows": 1},
                "auditAfter": {"artifacts": 6, "units": 12, "flows": 2},
                "membershipVerification": [{"artifactId": "mobbin-app-test", "units": 2, "flows": 1, "ok": True}],
                "verifiedAt": "2026-11-24T00:00:00+00:00"}

    def replay_setup(self, temp, receipt, batch_bytes=None, batch=None):
        """Seed the batch and receipt in R2 and return (env, fake_s3, openers)."""
        env = self.event_env(temp)
        fake_s3 = FakeS3()
        fake_s3.objects[self.batch_key] = (batch_bytes or self.batch_bytes, "application/json")
        receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
        fake_s3.objects[receipt_key] = (json.dumps(receipt).encode(), "application/json")
        openers = {}

        def make_opener(origin, bearer, oidc):
            if bearer not in openers:
                openers[bearer] = FakeOpener(bearer, batch or self.batch,
                                             self.audit_before, self.audit_after)
            return openers[bearer]

        return env, fake_s3, openers, make_opener

    def run_main(self, env, fake_s3, descriptor, make_opener):
        with patch.dict(os.environ, env), \
             patch("run_metadata_job.decrypt_descriptor",
                   return_value=json.dumps(descriptor)), \
             patch("run_metadata_job.r2_client", return_value=fake_s3), \
             patch("run_metadata_job.preview_opener", side_effect=make_opener):
            main()

    def test_replay_revalidates_batch_origin_and_memberships(self):
        # Review note 3: a receipt replays only after the batch is re-fetched
        # and hash/fingerprint-verified, the preview origin is checked, and a
        # fresh ordered membership readback matches the receipt exactly.
        with tempfile.TemporaryDirectory() as temp:
            env, fake_s3, openers, make_opener = self.replay_setup(temp, self.valid_receipt())
            self.run_main(env, fake_s3, self.descriptor, make_opener)
            read_opener = openers["agent-token"]
            self.assertEqual(read_opener.posts, [])
            self.assertTrue(any(u.endswith("/api/artifacts/mobbin-app-test") for u, _ in read_opener.gets))
            self.assertTrue(any(u.endswith("/api/imports/stored") for u, _ in read_opener.gets))
            self.assertEqual(len(fake_s3.objects), 2)  # no new objects written

    def test_replay_refuses_changed_preview_origin(self):
        other_origin = "https://taste-other-sams-projects-67b5023f.vercel.app"
        receipt = self.valid_receipt()
        receipt["previewOrigin"] = other_origin
        receipt["previewOriginSha256"] = sha(other_origin.encode())
        with tempfile.TemporaryDirectory() as temp:
            env, fake_s3, openers, make_opener = self.replay_setup(temp, receipt)
            with self.assertRaises(ValueError):
                self.run_main(env, fake_s3, self.descriptor, make_opener)
            self.assertEqual(sum(len(o.posts) for o in openers.values()), 0)

    def test_replay_refuses_changed_memberships(self):
        changed = make_batch()
        changed["units"][1]["order"] = 3  # the preview store no longer matches the receipt
        with tempfile.TemporaryDirectory() as temp:
            env, fake_s3, openers, make_opener = self.replay_setup(
                temp, self.valid_receipt(), batch=changed)
            with self.assertRaises(ValueError):
                self.run_main(env, fake_s3, self.descriptor, make_opener)
            self.assertEqual(sum(len(o.posts) for o in openers.values()), 0)

    def test_replay_refuses_tampered_batch(self):
        with tempfile.TemporaryDirectory() as temp:
            env, fake_s3, openers, make_opener = self.replay_setup(
                temp, self.valid_receipt(), batch_bytes=b"tampered bytes")
            with self.assertRaises(ValueError):
                self.run_main(env, fake_s3, self.descriptor, make_opener)
            self.assertEqual(sum(len(o.posts) for o in openers.values()), 0)

    def test_replay_refuses_swapped_batch_import(self):
        # Independent review (Samuel): a valid receipt for batch A presented
        # with a config authorizing batch B must be refused — the replay is
        # bound to the sealed config's batchKey/batchSha256, never to the
        # receipt's fields. Exact fixture case: descriptor batchKey
        # imports/source-files/<f*64>.json and batchSha256 f*64, with
        # valid_receipt() retained. No batch fetch or readback may be issued.
        swapped = dict(self.descriptor, batchKey="imports/source-files/" + "f" * 64 + ".json",
                       batchSha256="f" * 64)
        with tempfile.TemporaryDirectory() as temp:
            env, fake_s3, openers, make_opener = self.replay_setup(temp, self.valid_receipt())
            with self.assertRaises(ValueError):
                self.run_main(env, fake_s3, swapped, make_opener)
            self.assertEqual(openers, {})  # no preview request issued at all
            self.assertNotIn(self.batch_key, fake_s3.get_calls)  # no batch fetch
            self.assertEqual(sum(len(o.posts) for o in openers.values()), 0)
            self.assertEqual(len(fake_s3.objects), 2)  # no new objects written

    def valid_reconcile_receipt(self):
        return {"version": 1, "kind": "reconcile", "jobId": self.reconciliation_job_id,
                "jobSha256": hashlib.sha256(self.sealed).hexdigest(),
                "batchKey": self.reconciliation_key, "batchSha256": self.reconciliation_sha,
                "previewOrigin": ORIGIN, "previewOriginSha256": sha(ORIGIN.encode()),
                "reconciliationId": self.reconciliation["reconciliationId"],
                "applied": 2, "bulkVariantsRecorded": 2, "flowsVerified": 1, "replay": False,
                "auditBefore": {"artifacts": 5, "units": 10, "flows": 1},
                "auditAfter": {"artifacts": 6, "units": 12, "flows": 2},
                "membershipVerification": [{"artifactId": "mobbin-app-test", "units": 2, "flows": 1, "ok": True}],
                "verifiedAt": "2026-11-24T00:00:00+00:00"}

    def test_replay_refuses_swapped_batch_reconcile(self):
        # Same binding for kind:"reconcile": a valid receipt for one
        # reconciliation presented with a config authorizing a different batch
        # must be refused, with no batch fetch or readback issued.
        swapped = dict(self.reconciliation_descriptor,
                       batchKey="imports/source-files/" + "f" * 64 + ".json",
                       batchSha256="f" * 64)
        sealed_body = self.reconcile_body(swapped)
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=sealed_body)
            fake_s3 = FakeS3()
            fake_s3.objects[self.reconciliation_key] = (self.reconciliation_bytes, "application/json")
            receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
            fake_s3.objects[receipt_key] = (json.dumps(self.valid_reconcile_receipt()).encode(),
                                            "application/json")
            openers = {}

            def make_opener(origin, bearer, oidc):
                if bearer not in openers:
                    openers[bearer] = FakeOpener(bearer, self.batch, self.audit_before,
                                                 self.audit_after, reconcile=self.reconciliation)
                return openers[bearer]

            with self.assertRaises(ValueError):
                self.run_main(env, fake_s3, swapped, make_opener)
            self.assertEqual(openers, {})  # no preview request issued at all
            self.assertNotIn(self.reconciliation_key, fake_s3.get_calls)  # no batch fetch
            self.assertEqual(sum(len(o.posts) for o in openers.values()), 0)
            self.assertEqual(len(fake_s3.objects), 2)  # no new objects written

    def test_replay_refuses_oversize_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            fake_s3 = FakeS3()
            fake_s3.objects[self.batch_key] = (self.batch_bytes, "application/json")
            receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
            fake_s3.objects[receipt_key] = (b"x" * 1_000_001, "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before, self.audit_after)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener):
                with self.assertRaises(ValueError):
                    main()
                self.assertEqual(opener.posts, [])

    def test_reconcile_replay_returns_without_post(self):
        sealed_body = self.reconcile_body(self.reconciliation_descriptor)
        receipt = {"version": 1, "kind": "reconcile", "jobId": self.reconciliation_job_id,
                   "jobSha256": hashlib.sha256(self.sealed).hexdigest(),
                   "batchKey": self.reconciliation_key, "batchSha256": self.reconciliation_sha,
                   "previewOrigin": ORIGIN, "previewOriginSha256": sha(ORIGIN.encode()),
                   "reconciliationId": self.reconciliation["reconciliationId"],
                   "applied": 2, "bulkVariantsRecorded": 2, "flowsVerified": 1, "replay": False,
                   "auditBefore": {"artifacts": 5, "units": 10, "flows": 1},
                   "auditAfter": {"artifacts": 6, "units": 12, "flows": 2},
                   "membershipVerification": [{"artifactId": "mobbin-app-test", "units": 2, "flows": 1, "ok": True}],
                   "verifiedAt": "2026-11-24T00:00:00+00:00"}
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp, request_body=sealed_body)
            fake_s3 = FakeS3()
            fake_s3.objects[self.reconciliation_key] = (self.reconciliation_bytes, "application/json")
            receipt_key = "imports/metadata-job-receipts/" + hashlib.sha256(self.sealed).hexdigest() + ".json"
            fake_s3.objects[receipt_key] = (json.dumps(receipt).encode(), "application/json")
            openers = {}

            def make_opener(origin, bearer, oidc):
                if bearer not in openers:
                    openers[bearer] = FakeOpener(bearer, self.batch, self.audit_before,
                                                 self.audit_after, reconcile=self.reconciliation)
                return openers[bearer]

            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.reconciliation_descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", side_effect=make_opener):
                main()
            read_opener = openers["agent-token"]
            self.assertEqual(read_opener.posts, [])
            self.assertTrue(any(u.endswith("/api/artifacts/mobbin-app-test") for u, _ in read_opener.gets))
            self.assertEqual(len(fake_s3.objects), 2)  # no new objects written

    def test_oidc_mint_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            env = self.event_env(temp)
            fake_s3 = FakeS3()
            fake_s3.objects[self.batch_key] = (self.batch_bytes, "application/json")
            opener = FakeOpener("import-token", self.batch, self.audit_before, self.audit_after)
            with patch.dict(os.environ, env), \
                 patch("run_metadata_job.decrypt_descriptor",
                       return_value=json.dumps(self.descriptor)), \
                 patch("run_metadata_job.r2_client", return_value=fake_s3), \
                 patch("run_metadata_job.preview_opener", return_value=opener), \
                 patch("run_metadata_job.mint_github_oidc_token",
                       side_effect=ValueError("no token endpoint")):
                with self.assertRaises(ValueError):
                    main()
                self.assertEqual(opener.posts, [])

    def test_oidc_mint_caches_until_near_expiry_and_sends_audience(self):
        import time as time_module

        def token_with_exp(exp):
            header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).decode().rstrip("=")
            payload = base64.urlsafe_b64encode(
                json.dumps({"exp": exp, "iss": "https://token.actions.githubusercontent.com"}).encode()
            ).decode().rstrip("=")
            return f"{header}.{payload}.sig"

        class FakeMintOpener:
            def __init__(self, tokens):
                self.tokens = tokens
                self.calls = 0
                self.urls = []

            def open(self, request, timeout=None):
                self.urls.append(request.full_url)
                token = self.tokens[min(self.calls, len(self.tokens) - 1)]
                self.calls += 1
                resp = FakeResponse(json.dumps({"value": token}).encode())
                resp.status = 200
                return resp

        soon = int(time_module.time()) + 30
        first = token_with_exp(soon)
        second = token_with_exp(4102444800)
        fake = FakeMintOpener([first, second])
        env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://vstoken.actions.githubusercontent.com/abc?x=1",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token"}
        # setUp stands in a fake mint for the main() tests; this test exercises
        # the real mint, so restore it for the duration.
        import run_metadata_job
        with patch.dict(os.environ, env), \
             patch.object(run_metadata_job, "mint_github_oidc_token", mint_github_oidc_token), \
             patch("run_metadata_job.urllib.request.build_opener", return_value=fake):
            cache = OidcTokenCache(audience="my-audience")
            self.assertEqual(cache.get(), first)
            self.assertEqual(cache.get(), second)  # within the 60s refresh window: re-minted
            self.assertEqual(cache.get(), second)  # now cached
            self.assertEqual(fake.calls, 2)
            self.assertTrue(any("audience=my-audience" in url for url in fake.urls))

    def test_oidc_mint_refuses_foreign_host_and_non_jwt(self):
        env = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://evil.example.com/token",
               "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token"}
        with patch.dict(os.environ, env):
            with self.assertRaises(ValueError):
                mint_github_oidc_token()
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://vstoken.actions.githubusercontent.com/abc"
        resp = FakeResponse(json.dumps({"value": "not-a-jwt"}).encode())
        resp.status = 200

        class FakeMintOpener:
            def open(self, request, timeout=None):
                return resp

        with patch.dict(os.environ, env), \
             patch("run_metadata_job.urllib.request.build_opener", return_value=FakeMintOpener()):
            with self.assertRaises(ValueError):
                mint_github_oidc_token()

    @unittest.skipUnless(os.environ.get("TASTE_TEST_AGE_DIR"), "explicit pinned age directory required")
    def test_real_age_roundtrip_and_wrong_recipient(self):
        age = Path(os.environ["TASTE_TEST_AGE_DIR"]).resolve()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            identity_path = folder / "generated"
            subprocess.run([str(age / "age-keygen"), "-o", str(identity_path)],
                           capture_output=True, check=True)
            identity = identity_path.read_text()
            recipient = subprocess.run([str(age / "age-keygen"), "-y", str(identity_path)],
                                       capture_output=True, check=True).stdout.decode().strip()
            raw = json.dumps(self.descriptor, separators=(",", ":")).encode()
            sealed = subprocess.run([str(age / "age"), "-r", recipient], input=raw,
                                    capture_output=True, check=True).stdout
            request, decoded = parse_job_request(pack_job_request(self.job_id, sealed))
            from run_request import decrypt_descriptor
            self.assertEqual(decrypt_descriptor(decoded, identity, recipient, age, folder), raw.decode())
            self.assertFalse((folder / "identity").exists())
            with self.assertRaises(ValueError):
                decrypt_descriptor(decoded, identity, "wrong", age, folder)
            self.assertFalse((folder / "identity").exists())


if __name__ == "__main__":
    unittest.main()
