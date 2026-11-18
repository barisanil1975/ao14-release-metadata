# AO14 R186 — R180 full-payload RELEASE compatibility (OFFLINE candidate)

This branch is **code-only**. It does **not** modify the existing R171 workflow, `main`, Production, or native approval/lease records. Never put a real confidential approval payload, real cryptographic key, credential, host-state secret, customer data, or WAL into this public repository, PR, workflows, tests, logs, or artifacts.

## Exact wire contract

| Concern | Existing R171 (unchanged) | R186 / R180 offline candidate |
|---|---|---|
| Signed bytes | `AIOS.AO14.R171.RELEASE.DIGESTS.V1` followed by NUL, then two digest strings separated by newlines | `AIOS-AO14-R180-R175-APPROVAL-V1` followed by NUL and Python `json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)` |
| Approval envelope | Two SHA-256 digests | Exact 29-field R180 private approval payload with detached OWNER and RELEASE Ed25519 signatures |
| Candidate identity | R171 archive SHA | R175 ZIP SHA-256 `a47637dcc0e46f610f3ea8d7f43109c21094a5ada3264f157354acb71925dea8` |
| State binding | Insufficient for registrar grant | Independent 64-hex source / host-state / human approval digests, scope, nullable 40-hex Git SHA, short expiry and false effect flags |
| Authority | Digest-only public metadata | Synthetic signature compatibility only, not GRANTED, ACQUIRED, custody or live L4 |

`src/r180_release_offline.js` is a pure offline Node library: **no CLI signer, environment secret access, network, filesystem or workflow dispatch**. Signing is restricted to scopes of form `APV-AO14-R186-SYNTHETIC-*`, with ephemeral in-memory Ed25519 test key objects. The full-payload format is byte-compatible with R180 Python for this constrained JSON schema; 37 local Node tests and an independent Node-to-R180-Python verification passed before publication. The synthetic fixture is fabricated and is not an actual approval.

## Non-negotiable gates before any future live integration

- Independently held OWNER, RELEASE, AUDITOR and REGISTRAR trust roots. Different public keys are not proof of separate custody or independent audit.
- Independently pinned canonical root SHA, actual full approval payload and trusted current source/host/approval-text SHAs **outside this public repository**; verify fresh nonce, 15-minute validity and replay prevention.
- Existing R171 GitHub Actions secret approach must not be silently reused. The current digest-only workflow is neither compatible with R180 full approval nor a native execution authorization.
- A separately authorized *private* and data-class-allowlisted signing route must maintain separate principal and key custody. Do not transport confidential approval payloads through GitHub Actions public workflow inputs or logs.
- New native transactional registrar must be independently built and source-pinned under a new L4 approval; register GRANTED and ACQUIRED atomically and fail closed on any drift.
- Only later, under separate specific approval and a verified zero-incremental-cost bound, demonstrate encrypted WAL remote GET/SHA and TWO distinct real AO14 PostgreSQL 18 PITR recoveries without disturbing R112/FAIZ/Watchdog.

**R186 rollback:** Close the PR or delete its isolated branch. No merge, live signer, secret provisioning, Production change or fee is authorized by R186. The R171 workflow and `main` remain unchanged.
