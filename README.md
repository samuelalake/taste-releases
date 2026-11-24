# Taste Index release control

Public control code; private reference files and credentials. Uses standard GitHub-hosted Linux runners, as the existing May and Trove release-control repositories do. No paid runner or subscription is required. Normal GitHub usage limits still apply.

## Status

The protected runner has completed Cal AI and Alma byte transfers with full reader-key verification. Library metadata is a separate, preview-only operation through the reviewed `submitted-metadata-job.yml` workflow. See [metadata-job.md](docs/metadata-job.md) for setup and readback requirements. The synthetic check uses no credentials and is not evidence of a real import. Every real transfer requires separate owner review. No schedule or pull-request event can run it. Nothing here merges or deploys the Taste app.

## Cloud producer submission

`submitted-transfer.yml` accepts an **encrypted descriptor**, so a cloud producer no longer needs to set the `TASTE_BATCH_CONFIG` environment secret. The original `transfer.yml` manual path remains available. Both use the same protected environment, current-main checks, host allowlist, limits, immutable writes and full readback. The request is data; downloaded code is never executed.

1. Build and encrypt the ordinary bounded bundle as below. Host only ciphertext. Keep the plaintext descriptor in the producer's private workspace.
2. Use `tools/request_job.py --descriptor <private-json> --age <pinned-age> --recipient <reviewed-public-recipient> --host muse.ai --output <request-json>`. This encrypts the descriptor itself; the resulting request contains only version, opaque batch ID, encrypted-descriptor hash and base64 age ciphertext. The private download URL and queue fingerprint are inside the encryption.
3. Through a registered secure API-key connection, call `POST https://api.github.com/repos/samuelalake/taste-releases/actions/workflows/submitted-transfer.yml/dispatches` with `{"ref":"main","inputs":{"request":"<exact request JSON string>"}}`. A fine-grained GitHub token needs **Actions: read and write**, repository selection **taste-releases only**, and mandatory metadata read. No Contents, Secrets, Environments or Administration write access is needed. Never put that token in chat, request JSON, files, Git or logs. GitHub Actions permission also allows managing runs; this is not a dispatch-only credential.
4. Obtain the resulting run from the response if the API returns it; otherwise list this workflow's runs and identify the newly created run using its timestamp and actor. Dispatch only one batch at a time. Wait for and review its existing protected-environment approval. The cloud agent must present the private queue/cipher fingerprints for that specific batch before approval; public-key encryption alone is not authorization. The submitter credential does not change or remove the required reviewer.
5. Read the job result through GitHub's Actions API. A completed success plus `Transfer and full readback passed; library metadata unchanged` is the byte-transfer checkpoint. Failed or cancelled runs do not count. Keep the producer originals, save the run ID and counts privately, and revoke the temporary hosted ciphertext only after success.

The secure connection can be provisioned in Muse's normal custom API-key flow for `api.github.com`, using `Authorization: Bearer <secret>` and a short expiration. This setup must be explicitly approved before provisioning. It does not need a broader Meta Muse GitHub App installation or any R2 credentials in Muse. A real cloud-originated synthetic run is required before claiming that connection is operational.

The flow map must separately preserve source app/capture/screen IDs, gallery order and ordered flow membership. A flat PNG ZIP does not contain that map. A cloud browser can collect small strict-JSON chunks from rendered gallery and flow views with overlapping windows; persist and validate each chunk, then match exact image source values to source screen links. Do not infer missing flows from counts. Keep opaque source URLs in private provenance, not public control files.

References: [GitHub workflow dispatch permissions](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event), [workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

## Handoff

1. The producer constructs a ZIP_STORED archive containing `queue.json` and exactly the corresponding `objects/<sha256>.<extension>` files. `tools/bundle.py:pack` creates and checks this format. The queue has `version: 1` and an `objects` array; each row contains exactly `objectKey`, `sha256`, `bytes`, `contentType`. Source IDs and ordered flow/capture memberships belong in immutable JSON source envelopes, included as objects. The queue is for storage only; it is not a library manifest.
2. Encrypt the entire ZIP with the committed/reviewed public recipient: `age -r <recipient> -o bundle.age bundle.zip`. Use the pinned official age v1.3.1 tool from `tools/install_age.py`. The pin matches May's reviewed toolchain. No bespoke encryption format.
3. An approved temporary host receives only encrypted bytes. The producer still needs its own per-upload approval. Keep the URL, plaintext queue and detailed receipt out of this public repository, Actions inputs, public artifacts and logs. No screenshots are committed to Git. Expire the hosted ciphertext after collection.
4. The owner approves the exact queue fingerprint and ciphertext fingerprint in a private review. Put the batch descriptor in the environment secret `TASTE_BATCH_CONFIG` (see shape below), then dispatch only its random `batch_id`. Secrets are not accepted from the archive. The host must match the separately configured `TASTE_BUNDLE_HOST`; non-HTTPS URLs, private IPs and redirects are refused.
5. After environment review, the runner downloads and verifies ciphertext, decrypts to ephemeral disk, validates **every** file before writing anything, and uploads only hash-named objects to `taste-references`. Writes use `IfNoneMatch="*"`. An existing object is accepted only after full reader-key hash/length/type/metadata verification. A restart verifies every existing object again. No objects are overwritten or deleted.
6. Verified per-object receipts go to private R2 `imports/transfer-receipts/<receipt-sha256>.json`. A failed run makes no batch-success claim; retry is safe. Logs report only object counts and bytes. No public artifact is uploaded.
7. Import library metadata through Taste's existing guarded preview importer separately. Transfer jobs never change the Vercel Blob manifest. The separate metadata job can import only into the configured preview store; neither path confirms classifications or imports production metadata.

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

The encrypted-descriptor byte-transfer submission is verified from the cloud. The metadata workflow requires its own synthetic cloud pilot after the documented scoped preview-access setup. Private library indexing and rendered verification remain separate; do not describe a byte-transfer success as a completed reference import.
