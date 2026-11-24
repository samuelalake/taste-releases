#!/usr/bin/env python3
"""Build an age-encrypted metadata-job request from a batch already in private R2.

Producer-side only: it needs the public age recipient key and the batch's hash name, never a
secret. The batch JSON must already have been transferred immutably (see docs/metadata-job.md);
this script only seals the job descriptor that tells the runner which hash-named batch to apply
to the preview store. Prints the workflow_dispatch `request` JSON on stdout, nothing else.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sealed_metadata_request import job_descriptor, pack_job_request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-key", required=True,
                        help="Hash-named R2 key, e.g. imports/source-files/<sha256>.json")
    parser.add_argument("--batch-sha256", required=True)
    parser.add_argument("--kind", required=True, choices=("import", "reconcile"))
    parser.add_argument("--expires-at", required=True, help="ISO timestamp, at most 24h ahead")
    parser.add_argument("--recipient", required=True, help="Age public recipient key")
    parser.add_argument("--age-bin", default="age", help="Path to the pinned age binary")
    args = parser.parse_args()
    # jobId is the first 32 hex chars of the batch hash: deterministic, binds the job to the batch.
    descriptor = {"version": 1, "kind": args.kind, "jobId": args.batch_sha256[:32],
                  "batchKey": args.batch_key, "batchSha256": args.batch_sha256,
                  "expiresAt": args.expires_at, "preview": True}
    job_descriptor(json.dumps(descriptor, separators=(",", ":")))
    sealed = subprocess.run([args.age_bin, "--encrypt", "-r", args.recipient],
                            input=json.dumps(descriptor, separators=(",", ":")).encode(),
                            capture_output=True, check=True, timeout=30).stdout
    print(pack_job_request(descriptor["jobId"], sealed))


if __name__ == "__main__":
    main()
