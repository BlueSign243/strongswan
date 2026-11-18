# Aigis-sig Composite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Implement the experimental AigisSig2-SM3+Ed25519+SHA512-v1 profile, then document reproducible two-host certificate deployment after local tests pass.

**Architecture:** Follow `docs/aigis-sig-composite-ipsec-design.md`, preserving the KEM implementation. Use a checked PQMagic primitive helper, existing Ed25519 provider, strict DER credentials, and RFC 7427 AUTH with enforced M1/M2 policies.

**Tech Stack:** C, autotools, PQMagic std at 42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08, strongSwan test framework, Python unittest.

**Spec:** `docs/aigis-sig-composite-ipsec-design.md`

## Global Constraints

- mode 2 / SM3; Pure Ed25519; SHA-512; exact labels and framing from section 3.
- Raw public keys 1312/1344 bytes; signatures 2445/2509 bytes; seed 32/64 bytes.
- User authorized UUID-based OID generation; freeze the two X.667 2.25 OIDs in docs/aigis-sig-profile.json. Independent cryptographic analysis remains an experimental limitation.
- No commits during development/testing. No system installation or active configuration replacement.
- Preserve existing user document edits and Aigis-enc behavior.
- No production-readiness claim without cryptographic/dependency review; distinguish local tests from real ESP tests.

## Review Focus

- A wrong SHAKE library exporting the same API must fail signature variant checks.
- Empty, overflowing, inconsistent-pointer or oversized-context inputs must fail safely.
- Failure must empty outputs and wipe secret allocations; dependency internal cleanup limits must be recorded.
- Both signature components and complete key fingerprints must be checked.
- M2 must reject missing chain evidence and missing or mismatched explicit CA constraints.

### Task 1: D0 prerequisites and independent D1 dependency build

**Files:** `scripts/build-pqmagic-aigis.sh`, `scripts/tests/test_pqmagic_sign_build.py`, `docs/aigis-sig-implementation-progress.md`.
**Interfaces:** Keep two-argument KEM-only invocation; add third argument `--with-sign`; outputs `libpqmagic_std.so`, headers, correctness and provenance records.

- [x] Record baseline test results and external revision.
- [x] Test actual KEM-only vs KEM+signature symbol availability and unknown-option rejection; watch tests fail.
- [x] Build KEM and signature sources into distinct object directories; share hash/randombytes objects once.
- [x] Verify fixed seed, deterministic signature and ordinary/internal context API equivalence; record dependency audit.
- [x] Run build tests and old KEM tests; no Git commit.

### Task 2: D1 primitive helper and tests

**Files:** `src/libstrongswan/plugins/pqmagic/pqmagic_sig_params.h`, `pqmagic_aigis_sig.[ch]`, `scripts/tests/test_aigis_sig_primitive.c`, test runner.
**Interfaces:** Exact expand_seed/sign/verify/check_variant signatures from spec section 4. No key objects or wire OIDs before D0 resolves.

- [x] Capture independent upstream fixtures from public seed/message/context.
- [x] Write failing behavior tests: lengths, ordinary API equivalence, tampering, contexts 0/255/256, NULL pointers, size overflow, allocation failures and same-key concurrent sign/verify.
- [x] Implement checked helper/context framing, output cleanup and fixed SM3 KAT.
- [x] Run normal and sanitizer builds, plus same-symbol SHAKE negative tests.

### Task 3: D0 approval and D2 key objects/build integration

**Files:** profile and encoding files from spec section 4, key/scheme enums and maps, `configure.ac`, pqmagic plugin and Makefile, `test_aigis_sig.c`, `test_composite_aigis_sig.c`.

- [x] Freeze user-authorized UUID OIDs and the byte profile; independent cryptographic analysis remains pending.
- [x] Write and run failing object/provider/composite KAT tests.
- [x] Implement objects, existing Ed25519 provider use, SHA512 framing, RNG failure handling and optional plugin capability publishing.
- [x] Verify both-component mutations, provider absence, concurrency and disabled-signature builds.

### Task 4: D3 credentials and PKI

**Files:** strict encoding implementation, `oid.txt`, pkcs1/pkcs8 dispatch, PEM encoding, pki command files and manuals; `test_pqmagic_credentials.c`, `test_signature_params.c`.

- [x] Write failing strict DER tests and pki subprocess round trips.
- [x] Implement authorized OID mappings, full SPKI/PKCS8 loaders and complete key fingerprints.
- [x] Generate and verify M1 and M2 certificates/CSR; reject malformed DER, mismatched digest, TBS/key/issuer mutations.

### Task 5: D4 AUTH and M1/M2 enforcement

**Files:** `pubkey_authenticator.c`, `auth_cfg.c`, `vici_config.c`, swanctl documentation, auth_cfg/signature_params tests, `test_aigis_sig_auth.c` and exchange suite registration.

- [x] Write failing RFC7427 boundary, real composite AUTH, IntAuth tamper and policy tests.
- [x] Implement exact AlgID slicing and absent parameters; strict profile parsing and chain evidence enforcement.
- [x] Run initiator/responder initial AUTH with real providers; confirm no fallback under negative inputs.
- [ ] Verify complete reauthentication, real ESP and network loss on two hosts (D6 deployment acceptance).

### Task 6: D5 regression and D6 deployment artifact

**Files:** `testing/tests/ikev2/host2host-aigissig/`, `docs/aigis-sig-build-and-test.md`, progress evidence.

- [x] Run build matrix, complete make check and Python helper tests; record exact executed suites and limitations.
- [x] Review changes and test evidence; fix substantive findings with regression tests.
- [x] After local signature/credential/protocol tests pass, write exact tested mixed-certificate generation, moon/sun configurations, deployment, fragmentation/reauth/ESP acceptance and rollback steps.
- [x] No claim of real two-host acceptance without running it. No Git commit before local tests pass.

## Completion boundary

D1–D5 local engineering implementation and review are complete, subject to final recorded regression results in `docs/aigis-sig-implementation-progress.md`. D0 independent cryptographic analysis and D6 real two-host acceptance are not claimed. The deployment document supplies the pending acceptance steps. No system installation or remote changes were performed.
