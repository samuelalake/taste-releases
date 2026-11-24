# Taste Index release control

Public control code; private reference files and credentials. Uses standard GitHub-hosted Linux runners, as the existing May and Trove release-control repositories do. No paid runner or subscription is required. Normal GitHub usage limits still apply.

## Status

The synthetic check needs no credentials and tests actual age encryption/decryption plus an in-memory storage stand-in. It does **not** prove Muse file hosting, R2 access or Taste library indexing. The real transfer refuses admission until the protected environment is configured; it requires separate owner review for each run. No schedule or pull-request event can run it. Nothing here merges or deploys the Taste app.

## Handoff

1. The producer constructs a ZIP_STORED archive containing `queue.json` and exactly the corresponding `objects/<sha256>.<extension>` files. `tools/bundle.py:pack` creates and checks this format. The queue has `version: 1` and an `objects` array; each row contains exactly `objectKey`, `sha256`, `bytes`, `contentType`. Source IDs and ordered flow/capture memberships belong in immutable JSON source envelopes, included as objects. The queue is for storage only; it is not a library manifest.
2. Encrypt the entire ZIP with the committed/reviewed public recipient: `age -r <recipient> -o bundle.age bundle.zip`. Use the pinned official age v1.3.1 tool from `tools/install_age.py`. The pin matches May's reviewed toolchain. No bespoke encryption format.
3. An approved temporary host receives only encrypted bytes. The producer still needs its own per-upload approval. Keep the URL, plaintext queue and detailed receipt out of this public repository, Actions inputs, public artifacts and logs. No screenshots are committed to Git. Expire the hosted ciphertext after collection.
4. The owner approves the exact queue fingerprint and ciphertext fingerprint in a private review. Put the batch descriptor in the environment secret `TASTE_BATCH_CONFIG` (see shape below), then dispatch only its random `batch_id`. Secrets are not accepted from the archive. The host must match the separately configured `TASTE_BUNDLE_HOST`; non-HTTPS URLs, private IPs and redirects are refused.
5. After environment review, the runner downloads and verifies ciphertext, decrypts to ephemeral disk, validates **every** file before writing anything, and uploads only hash-named objects to `taste-references`. Writes use `IfNoneMatch="*"`. An existing object is accepted only after full reader-key hash/length/type/metadata verification. A restart verifies every existing object again. No objects are overwritten or deleted.
6. Verified per-object receipts go to private R2 `imports/transfer-receipts/<receipt-sha256>.json`. A failed run makes no batch-success claim; retry is safe. Logs report only object counts and bytes. No public artifact is uploaded.
7. Import library metadata through Taste's existing guarded preview importer separately. This runner never changes the Vercel Blob manifest, confirms classifications or imports production metadata.

Bounds: 64 MiB ZIP, 512 objects, 16 MiB per object; PNG, JPEG, PDF and JSON only; 15-minute transfer job, serial operations. Split larger exports into separately approved batches. Original files stay with the producer. Temporary plaintext is removed on normal success/failure by the Python context manager; the GitHub-hosted VM is discarded after the job. Cancellation may prevent Python cleanup, so never use this on a persistent self-hosted runner.

## Protected setup

Repository: `samuelalake/taste-releases`; environment: `taste-reference-transfer`.

- Required reviewer: Samuel (`58840187`), exactly one reviewer. Allow self-review so the sole owner can approve his own dispatch; disable administrator bypass.
- Custom deployment branch policy: **branch main only**, no tags. The gate checks these settings before secrets and again after review; it also requires the current main SHA and a manual dispatch.
- Environment secrets: `TASTE_AGE_IDENTITY`, `TASTE_BATCH_CONFIG`, `TASTE_R2_ACCOUNT_ID`, `TASTE_R2_WRITER_ACCESS_KEY_ID`, `TASTE_R2_WRITER_SECRET_ACCESS_KEY`, `TASTE_R2_READER_ACCESS_KEY_ID`, `TASTE_R2_READER_SECRET_ACCESS_KEY`.
- Environment variables: `TASTE_AGE_RECIPIENT` (public key), `TASTE_BUNDLE_HOST` (exact approved ciphertext-host domain).
- Only use existing bucket-scoped R2 credentials via an approved secret-store-to-GitHub transfer. Never provision a broad Bitwarden access token here. No Taste owner password or production import token is needed.
- Changing the public control code requires review before a secret-bearing run. Environment approval is not a substitute for code review. No untrusted branch or downloaded code is executed with these secrets.

Private batch descriptor (values are deliberately placeholders):

```json
{"batchId":"<32 lowercase hex>","expiresAt":"<UTC ISO timestamp, within 24 hours>","bundleUrl":"<HTTPS ciphertext URL>","cipherSha256":"<64 lowercase hex>","queueSha256":"<64 lowercase hex>"}
```

The descriptor's ID must equal the dispatch input. Queue and ciphertext fingerprints are owner-approved separately from the file host: anyone knowing the public key can encrypt a file, so encryption alone is not sender authorization. An expired descriptor fails closed. Rotate the batch descriptor for each new batch; a changed descriptor causes old queued IDs to fail rather than run another batch.

## Verification

`python3 -B -m unittest discover -s tests` exercises invalid bundles, wrong hashes, traversal/extra files, rejected hosts/expired descriptors, fail-closed admission, full readback, collision handling and replay. `python3 tools/install_age.py` then `python3 tools/smoke.py` checks the actual pinned age binary with synthetic data only; set `RUNNER_TEMP` to a disposable private directory locally.

Known unproved stages until a real pilot: Muse encrypted-file hosting, protected-environment API admission on this repo, R2 access from this runner, per-object receipts, and private metadata import. Do not describe synthetic success as a completed reference import.
