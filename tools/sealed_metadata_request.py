"""Submitted metadata job: only an age-encrypted job descriptor; never a URL, host, credential, or batch content."""
import base64
import binascii
import hashlib
import json
import re
from datetime import datetime, timezone

from bundle import require, unique_json

MAX_REQUEST = 16_384
MAX_SEALED = 10_240
MAX_DESCRIPTOR = 4_096

# The batch payload lives in private R2 under a hash name; the key IS its SHA-256.
# It rides the existing `imports/source-files/` prefix (the same prefix the transfer
# bundle accepts); there is no separate `metadata-jobs` prefix. A metadata-job
# payload can never be mistaken for a source envelope: envelopes are the capture's
# own source file, while a job payload is a StoredBatch or a
# SameCaptureReconciliation whose own fingerprint is checked after the fetch.
JOB_KEY = re.compile(r"^imports/source-files/[0-9a-f]{64}\.json$")


def parse_job_request(body):
    require(isinstance(body, str) and len(body.encode()) <= MAX_REQUEST)
    request = unique_json(body)
    require(isinstance(request, dict))
    require(set(request) == {"version", "jobId", "jobSha256", "sealedJob"})
    require(type(request["version"]) is int and request["version"] == 1)
    require(isinstance(request["jobId"], str) and re.fullmatch("[0-9a-f]{32}", request["jobId"]))
    require(isinstance(request["jobSha256"], str) and re.fullmatch("[0-9a-f]{64}", request["jobSha256"]))
    require(isinstance(request["sealedJob"], str))
    try:
        sealed = base64.b64decode(request["sealedJob"], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid request") from None
    require(100 <= len(sealed) <= MAX_SEALED and sealed.startswith(b"age-encryption.org/v1\n"))
    require(hashlib.sha256(sealed).hexdigest() == request["jobSha256"])
    return request, sealed


def pack_job_request(job_id, sealed):
    request = {"version": 1, "jobId": job_id,
               "jobSha256": hashlib.sha256(sealed).hexdigest(),
               "sealedJob": base64.b64encode(sealed).decode("ascii")}
    body = json.dumps(request, separators=(",", ":"))
    parse_job_request(body)
    return body


def job_descriptor(raw):
    """Validate the decrypted job descriptor. Preview-only: any production target is refused here."""
    config = unique_json(raw)
    require(set(config) == {"version", "kind", "jobId", "batchKey", "batchSha256", "expiresAt", "preview"})
    require(type(config["version"]) is int and config["version"] == 1)
    require(config["kind"] in ("import", "reconcile"))
    require(isinstance(config["jobId"], str) and re.fullmatch("[0-9a-f]{32}", config["jobId"]))
    require(isinstance(config["batchKey"], str) and JOB_KEY.fullmatch(config["batchKey"]))
    require(isinstance(config["batchSha256"], str) and re.fullmatch("[0-9a-f]{64}", config["batchSha256"]))
    require(config["batchSha256"] == config["batchKey"].split("/")[-1].split(".")[0])
    require(config["preview"] is True)
    remaining = (datetime.fromisoformat(config["expiresAt"].replace("Z", "+00:00")) - datetime.now(timezone.utc)).total_seconds()
    require(0 < remaining <= 86400)
    return config
