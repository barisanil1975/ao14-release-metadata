# AO14 R171 — Public digest-only RELEASE signer (candidate)

This public code signs **only two SHA-256 digests** (approval receipt and immutable candidate archive) with an environment-scoped Ed25519 key after a GitHub Environment deployment review. No customer data, private approval receipt, production backup, or private key is included.

**Status:** Code-only candidate. No signing key is provisioned and no Production approval, L4 grant, lease, deployment, or restore is created by this repository.

The workflow is manual (`workflow_dispatch`), scoped to `main`, and references a protected environment named `ao14-release-reviewed`. An environment name in YAML does **not** prove that GitHub required-reviewer protection exists: repository administrators must configure and verify it separately. Do not dispatch until reviewer protection, exact commit pinning, repository visibility, independent key custody, and complete approval-context validation have been reviewed and accepted under a separate authorization.

The public workflow uses standard GitHub-hosted `ubuntu-latest` only. It intentionally performs no checkout, install, network transfer, or production action.

Run local synthetic tests with `node --test tests/test_release.js`. Signature verification alone is **not** sufficient for authorization; any downstream registrar must independently verify the exact private approval payload, OWNER signature, source state, expiry, nonce, GitHub approval event and immutable workflow commit, GRANTED/ACQUIRED gate, and action scope.
