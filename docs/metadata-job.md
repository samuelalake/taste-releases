# Submitted private metadata job

Applies an already-transferred batch to the **preview store only**, from the cloud, without
the producer ever holding a Taste credential. Modelled on `submitted-transfer.yml` and reuses
its gate, descriptor, bundle and transfer validation; it adds no new trust root.

## What it does, in order

1. **Admission** (`tools/gate.py`, before review and again after): workflow_dispatch on
   protected `main` at the reviewed commit, protected environment
   `taste-reference-transfer` with the owner (58840187) as sole reviewer, no admin bypass.
   The submitted request is shape-checked in admission; nothing secret is needed to do it.
2. **Decrypt** (`tools/run_metadata_job.py`): the sealed job is decrypted with the protected
   `TASTE_AGE_IDENTITY`; the derived recipient must equal `TASTE_AGE_RECIPIENT`. The
   decrypted descriptor is at most 4,096 bytes.
3. **Fetch by hash name**: the batch JSON is fetched from private R2 at
   `imports/source-files/<sha256>.json` with the reader key and its SHA-256 is verified.
   No caller-supplied URL or host is ever used. The payload rides the existing
   transfer prefix — there is no separate `metadata-jobs` prefix.
4. **Fingerprint check**: the batch's own `batchId` must equal the canonical digest of the
   rest of the payload (the same `digestData` algorithm as `src/lib/importStored.ts`;
   verified byte-identical against the TypeScript implementation on fixtures). A
   reconciliation payload's `reconciliationId` is checked the same way against
   `reconciliationDigest`.
5. **POST the preview route only**: `POST {TASTE_PREVIEW_ORIGIN}/api/imports/stored` with
   `Authorization: Bearer <TASTE_IMPORT_TOKEN>` and the `x-vercel-trusted-oidc-idp-token`
   bypass header. The origin is the fixed owner-configured `TASTE_PREVIEW_ORIGIN` var
   (https `*.vercel.app`, empty path). Retries only 429/500/502/503/504, three attempts.
   The OIDC token is minted fresh per run (see "Authentication" below) — no static
   bypass secret is provisioned, read, or accepted.
6. **Verify every flow membership**: `GET /api/imports/stored` audit before and after
   (units delta must equal `created`, `allFlowMembersResolve` must be true) and
   `GET /api/artifacts/<id>` for every artifact in the batch, comparing each unit's
   `(id, order)` and each flow's member `(unitId, order)` sequence exactly. For a
   reconciliation the runner checks the response (`applied`, `bulkVariantsRecorded`,
   `flowsVerified`, `replay`) and then reads back every moved unit at its target
   order and every verified flow (name, source URL, member sequence) from the live
   preview store.
7. **Private receipt**: `imports/metadata-job-receipts/<jobSha256>.json` in R2, written
   immutably (`IfNoneMatch: '*'`) and read back with the reader key. A second dispatch of
   the same job does not replay on the receipt alone: it re-fetches the batch and
   verifies its SHA-256 and fingerprint, checks the receipt's preview origin against
   the configured origin, and performs a fresh ordered membership readback that must
   match the receipt exactly. **Replay binding:** the replay is bound to the sealed
   config — the job carries the config's `batchKey` and `batchSha256`, the receipt's
   `batchKey` and `batchSha256` must equal them exactly, and the batch is re-fetched
   by the config-authorized key. A receipt for a different batch can never replay:
   a swapped-batch replay is refused before any batch fetch or readback
   (regression-tested for both `import` and `reconcile`). Any mismatch fails the
   job; nothing is re-posted.
8. **Logs** carry only fixed strings and counts (`jobId`, `created`, `exists`,
   `flowsVerified`). No credentials, URLs, or source metadata.

## Request schema

Outer `workflow_dispatch` input `request` (string, at most 16,384 bytes), parsed by
`tools/sealed_metadata_request.py:parse_job_request`:

```json
{"version": 1, "jobId": "<32 hex>", "jobSha256": "<64 hex>", "sealedJob": "<base64>"}
```

- `version` is the integer `1`; `jobId` is `[0-9a-f]{32}`; `jobSha256` is `[0-9a-f]{64}`.
- `sealedJob` base64-decodes to 100–10,240 bytes starting with `age-encryption.org/v1\n`,
  and `sha256(sealed) == jobSha256`. No other keys are allowed: no URL, host, path, or
  credential can enter.

Decrypted job descriptor (at most 4,096 bytes), validated by `job_descriptor`:

```json
{"version": 1, "kind": "import", "jobId": "<32 hex>",
 "batchKey": "imports/source-files/<64 hex>.json", "batchSha256": "<64 hex>",
 "expiresAt": "<ISO, at most 24h ahead>", "preview": true}
```

- `kind` is `import` or `reconcile`. `jobId` is the first 32 hex chars of `batchSha256`
  (the producer uses this deterministic identifier) and must equal the outer `jobId`.
- `batchKey`'s stem must equal `batchSha256`: the key IS the hash name.
- `preview` must be literally `true`. Any production target (`preview: false`, a
  `target` field, or any extra key) is refused before any fetch or POST.
- `expiresAt` must be in the future and at most 24 hours ahead.

## The batch payload

A `StoredBatch` JSON (`{batchId, artifacts, units, flows, objects}`, `batchId` the
64-hex canonical digest of the rest), produced by the existing
`tools/prepare_library_import.py` flow and transferred immutably first. It rides a
transfer bundle as an `imports/source-files/<sha256>.json` object — the same prefix
`tools/bundle.py` already accepts for JSON (the patch's two-line addition of a
separate `metadata-jobs` prefix was reverted; batch payloads are not source
envelopes, and the two are told apart by their own fingerprint, checked after the
fetch, not by the prefix). At most 4,000,000 bytes: the route rejects larger bodies.

## Reconciliation payloads

`kind: "reconcile"` carries a #34-style `SameCaptureReconciliation` payload at the same
hash-named `imports/source-files/<sha256>.json` key, fingerprinted by
`reconciliationDigest` (the same canonical digest). The runner posts it to the
guarded preview reconciliation route `POST /api/imports/reconcile` (Taste PR #34,
head `3ec69af`: owner session or import token, preview-only, exact
`reconciliationDigest`, response `{reconciliationId, applied,
bulkVariantsRecorded, flowsVerified, replay, audit}`), then reads back every
moved unit and verified flow. The route is implemented in a separate draft PR; the runner accepts
`kind: "reconcile"`. Reconciliation payloads are at most 1,000,000 bytes: the
route rejects larger bodies.

## Authentication — renewable OIDC, no static bypass secret

The preview deployment is protected, and the runner authenticates with a
short-lived GitHub Actions OIDC token minted per run — never a static
`VERCEL_OIDC_TOKEN` (which expires and would need re-provisioning):

- The workflow grants the `metadata` job `id-token: write` permission.
- `tools/run_metadata_job.py` mints the token from the runner's own token
  endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN`),
  reads only its `exp` claim to know when to re-mint (60 seconds before expiry),
  and sends it as `x-vercel-trusted-oidc-idp-token`. The JWT signature is
  verified by Vercel, not by the runner.
- **Owner-side setup (once, in the Vercel dashboard):** Settings → Deployment
  Protection → Trusted Sources — add GitHub Actions as a trusted OIDC provider,
  restricted to repository `samuelalake/taste-releases`, branch `main`, workflow
  `Submitted private metadata job`, GitHub environment `taste-reference-transfer`,
  and destination Vercel environment `preview`. Require these claims together
  in one rule; preserve existing Trusted Sources rules when configuring it. The rule must accept the token's issuer
  (`https://token.actions.githubusercontent.com`) and its audience: by default
  GitHub's audience is the repository owner's URL; a custom audience can be set
  with the `VERCEL_OIDC_AUDIENCE` var, in which case the Trusted Sources rule
  must accept that audience instead. Until that rule exists, the preview route
  refuses the minted token and the job fails closed — nothing is posted.
- **Scoping rule for the eventual Trusted Sources rule:** scope it to the exact
  protected workflow, ref, and environment — the `submitted-metadata-job`
  workflow on protected `main` in the `taste-reference-transfer` environment —
  not merely the public repository. A repository-wide rule would let any
  workflow in the repository mint an accepted token; the narrow scope is what
  makes the minted token an authorization for this job only. **No such rule has
  been granted** — this is a requirement for the eventual setup, not a claim
  that it exists.
- No `VERCEL_OIDC_TOKEN` secret is provisioned anywhere. If one was ever set in
  the environment, the runner ignores it (a test asserts the minted token, not
  any static value, is the one sent).

## Producer: sealing a job request

```sh
python3 tools/pack_job_request.py \
  --batch-key imports/source-files/<sha256>.json --batch-sha256 <sha256> \
  --kind import --expires-at <ISO, <=24h> \
  --recipient <age public key> --age-bin <pinned age binary>
```

Prints the `request` JSON for the dispatch. It needs only the public recipient key;
no secret. (The transfer-side analogue is `tools/request_job.py`.)

## Dispatch (cloud runner, custom API-key Actions connector)

```sh
# POST https://api.github.com/repos/samuelalake/taste-releases/actions/workflows/submitted-metadata-job.yml/dispatches
# Authorization: Bearer <fine-grained PAT: samuelalake/taste-releases, Actions read/write>
{"ref": "main", "inputs": {"request": "<output of pack_job_request.py>"}}
```

The run then waits for the protected-environment review by the owner before the
`metadata` job executes. Nothing in the dispatch carries a secret.

## Protected environment `taste-reference-transfer` — names only, no values

New secrets (provisioned by the authorized operator, never exposed to the producer):

- `TASTE_IMPORT_TOKEN` — preview-only import token; `Bearer` for `POST /api/imports/stored`
  and `POST /api/imports/reconcile`. Must differ from `TASTE_AGENT_TOKEN` (the route
  refuses a misconfiguration that equates them).
- `TASTE_AGENT_TOKEN` — read-only agent token; `Bearer` for `GET /api/imports/stored` and
  `GET /api/artifacts/<id>`.

There is no `VERCEL_OIDC_TOKEN` secret: the runner mints a short-lived GitHub OIDC
token per run (see "Authentication" above). Do not provision one.

New vars (owner-configured):

- `TASTE_PREVIEW_ORIGIN` — fixed preview origin, e.g.
  `https://taste-<hash>-sams-projects-67b5023f.vercel.app`.
- `VERCEL_OIDC_AUDIENCE` — optional; a custom audience for the minted OIDC token.
  Empty means GitHub's default audience (the repository owner's URL). The Vercel
  Trusted Sources rule must accept whichever audience is configured here.

Already in the environment (unchanged): `TASTE_AGE_IDENTITY`, `TASTE_R2_ACCOUNT_ID`,
`TASTE_R2_WRITER_ACCESS_KEY_ID`, `TASTE_R2_WRITER_SECRET_ACCESS_KEY`,
`TASTE_R2_READER_ACCESS_KEY_ID`, `TASTE_R2_READER_SECRET_ACCESS_KEY`,
`TASTE_AGE_RECIPIENT` (var).

## What this job cannot do

- Touch production: there is no production code path, no production token, and the
  descriptor refuses any non-preview target. Production import stays the owner-reviewed
  exact-batch approval in `TASTE_PRODUCTION_IMPORT_APPROVAL` (see `taste` docs).
- Change an image or an owner classification: the preview route runs the same
  `applyStoredBatch` conflict checks; a changed image key or a source-identity conflict
  returns 409 and no receipt is written.
- Overwrite a receipt or a batch object: all R2 writes are `IfNoneMatch: '*'`.
- Run without review: the `metadata` job needs the protected-environment approval, and
  `gate.py` re-checks protected main after review.

## Not activated — checklist before the first real dispatch

- [ ] This PR is reviewed and merged to `main` (dispatch requires `main`; `gate.py`
      enforces the ref and the reviewed commit).
- [ ] `TASTE_IMPORT_TOKEN`, `TASTE_AGENT_TOKEN` provisioned in the protected
      environment (names only above; values never in chat, files, or logs).
      No `VERCEL_OIDC_TOKEN` is provisioned — the runner mints its OIDC token.
- [ ] The Vercel Trusted Sources rule for GitHub Actions is configured on the
      Taste project (see "Authentication" above), scoped to the exact protected
      workflow, ref, and environment (`submitted-metadata-job` on protected
      `main` in `taste-reference-transfer`), not merely the public repository,
      accepting the configured audience (`VERCEL_OIDC_AUDIENCE` if set, else
      GitHub's default). No such rule has been granted yet.
- [ ] `TASTE_PREVIEW_ORIGIN` set to the reviewed preview deployment.
- [ ] The preview deployment is built from a `taste` commit that includes the guarded
      `POST /api/imports/stored` route and the preview store separation — and the
      guarded `POST /api/imports/reconcile` route (Taste PR #34) before any
      `kind: "reconcile"` job is submitted.
- [ ] A synthetic metadata job (tiny batch, synthetic content) is dispatched, reviewed,
      and verified end to end before any real batch.
