# PR #90 split — fork status (A / B / C)

**Status date:** 2026-07-25  
**Audience:** maintainers working on the `omonien` fork  
**Policy:** work stays on the **fork only** until earlier open PRs against `MHumm/development` are reviewed. **Do not open A/B/C against upstream yet** unless that policy changes.

This document is the **index**. Per-package design lives in the linked plans. Code lives on the package branches (not necessarily on `development` yet).

---

## Why this exists

Open contribution [PR #90](https://github.com/MHumm/DelphiEncryptionCompendium/pull/90) mixed two concerns (AEAD architecture + ChaCha/Poly1305) plus AES-NI. Merging it as one unit was rejected; work was re-landed as reviewable packages on the fork.

Branch ancestry alone shows *what* is stacked. This file records *intent*, *order*, and *what not to do*.

---

## Package stack (fork)

```
origin/development
 └── package/aead-architecture     (A)  AEAD FAuthObj + multi-call GCM
      └── package/chacha-poly1305  (B)  ChaCha20 / XChaCha20 / Poly1305
           └── package/aes-ni      (C)  AES-NI with mandatory pure-Pascal fallback
```

| Package | Branch | Fork PR (internal) | Detail plan |
|---------|--------|--------------------|-------------|
| **A** Architecture | `package/aead-architecture` | [omonien#5](https://github.com/omonien/DelphiEncryptionCompendium/pull/5) | [2026-07-25-aead-architecture.md](./2026-07-25-aead-architecture.md) |
| **B** ChaCha/Poly1305 | `package/chacha-poly1305` | [omonien#6](https://github.com/omonien/DelphiEncryptionCompendium/pull/6) | [2026-07-25-chacha-poly1305.md](./2026-07-25-chacha-poly1305.md) |
| **C** AES-NI | `package/aes-ni` | [omonien#7](https://github.com/omonien/DelphiEncryptionCompendium/pull/7) | [2026-07-25-aes-ni.md](./2026-07-25-aes-ni.md) |

Fork PRs #5–#7 are for **tracking / internal review** on the fork. They are not a substitute for future PRs into `MHumm/DelphiEncryptionCompendium`.

---

## Upstream strategy (when ready)

Target base for each: **`MHumm/development`** (not `master`), after any prerequisite cleanup PRs Markus has accepted.

| Step | Open against `MHumm/development` | Head (fork) | Depends on |
|------|----------------------------------|-------------|------------|
| 1 | Package A | `omonien:package/aead-architecture` | Current `development` |
| 2 | Package B | `omonien:package/chacha-poly1305` | **A merged** (else re-target / restack) |
| 3 | Package C | `omonien:package/aes-ni` | **B merged** (or A+B equivalent) |

**Do not** open B or C against upstream before A is in (or carefully restacked onto post-A `development`).

### Relation to other work

| Item | Role |
|------|------|
| [PR #90](https://github.com/MHumm/DelphiEncryptionCompendium/pull/90) | **Donor / reference only** — do not merge as a single unit |
| GCM multi-chunk (fork `pr-fix-gcm-multichunk` / upstream PR #99 if still open) | Semantics **absorbed into A**; if #99 merges first, expect a small GCM-file conflict when landing A |
| Older fork cleanup branches (`pr-gitignore`, `pr-dunitx-migration`, Keccak/SHA3 fixes, `docs/style-guide`, …) | Independent of A/B/C; leave until Markus finishes those reviews |
| Residual Keccak unit failures on `development` | Pre-existing; not introduced by A/B/C |

---

## One-line package summaries

- **A:** One `FAuthObj` for authenticated modes; GCM multi-call + `Done` lifecycle; public `IDECAuthenticatedCipher` unchanged; no ChaCha.
- **B:** ChaCha20 / XChaCha20 / Poly1305 on A’s lifecycle; AEAD opt-in (`cmPoly1305`); portable PAS default for SIMD.
- **C:** AES-NI on x86/x64 only when compiled and CPU supports it; **pure Pascal always remains**; no ARM Crypto Extensions yet.

---

## Verification snapshot (at package completion)

Delphi 13, Win32 Console DUnit (`DECDUnitTestSuite`), run from `Compiled/BIN_IDE_Win32_Console`:

| After | Notable green suites |
|-------|----------------------|
| A | GCM multi-chunk + Done lifecycle; CCM regression |
| B | + ChaCha20Poly1305 suite; GCM/CCM still green |
| C | + AES-NI FIPS KATs and PAS↔AES-NI match; ChaCha/GCM/CCM still green |

Known reds on full suite at that time: pre-existing **Keccak** vector issues only (separate fix PRs).

---

## Hygiene (not done yet — intentional)

- Old `pr-*` / `Cleanup_OM` / `docs/style-guide` branches remain on the fork until earlier upstream reviews settle.
- Local `pr-90` ref (if present) is only a donor checkout; safe to delete anytime.
- After each package merges upstream, the corresponding `package/*` branch can be deleted or archived.

---

## This docs branch

**Branch:** `docs/pr90-split-status`  
**Contents:** this index + copies of the three package plans (so the branch is readable without checking out A/B/C).  
**Code:** none. Safe to open as a docs-only PR to the fork or to upstream later if useful.

When a package plan is updated on `package/*`, refresh the copy here if this branch is still the status SSOT.
