# Session 2026-11-16 — Secure channel applet + Oracle simulator bring-up

## Goals
- (Earlier phase) Add `SecureChannelApplet` (ECDH P-256 + HKDF-SHA-256 +
  AES-256-GCM, protocol "SC v1") alongside HelloWorld; 2 applets in one CAP.
  → Implemented, 12 jCardSim integration tests green.
- (This phase) Test the CAP end-to-end in the **Oracle Java Card simulator v26**
  inside the local `docker-javacard` image, including a real handshake.
  → **Achieved: 18/18 smoke checks PASS on Oracle, 12/12 green on jCardSim.**

## Preferences
- Ask before git commit; never push. User wants to review before deciding
  commit scope/granularity → **multiple thematic commits, later, not yet**.
- Session summaries in `.opencode/session-*.md`; TODOs in `.opencode/TODOs.md`
  (mark done only after commit).
- "Schmal, aber sicher" — lean, standard-only crypto; portability over tricks.

## Environment / setup (works)
- Image: built locally from `~/Documents/coding/javacard/docker-javacard`
  (pinned rev `690f4db`) with `--build-arg
  JAVACARD_SIMULATOR=java_card_devkit_simulator-linux-bin-v26.0-b_788-05-MAY-2026.tar.gz`
  → tag `docker-javacard`.
- Container flow: entrypoint starts Oracle `jcsl -p=9025 -log_level=finest`
  (PC/SC reader; `/var/log/jcsl.log` = **gold for debugging**).
- Harness: `simulator/OracleSimulatorSmokeTest.java` — dependency-free
  single-file Java (`javax.smartcardio` + JCE), compiled inside the container.
  Selects both applets, full handshake, ping round trips, replay/tamper
  rejection + wipe, re-handshake, deselect wipe.
- Install flow for a two-applet CAP:
  ```bash
  gp --install ./helloworld.cap --applet 010203040506      # LOAD + 1st instance
  gp --create 010203040507 --package 0102030405 --applet 010203040507  # 2nd instance
  ```
  - `gp --install` refuses multi-applet CAPs without `--applet <AID>`
    (AID, NOT class name).
  - A second `gp --install` = package reload → `0x6985`. Use `gp --create`.

## Debugging chronicle (Oracle failures → fixes)

### Failure 0: harness compile errors (trivial)
- `javax.smartcardio.Terminals` doesn't exist → `TerminalFactory.getDefault()
  .terminals().list()`; `Card` has no `getTerminal()`.

### Failure 1: EXCHANGE → SW 6F00 (uncaught applet exception)
- `jcsl.log`: `CryptoException reason=0x0001` (ILLEGAL_VALUE), stack unresolved.
- Debug method: temporary stage byte + debug INS + SW `0x6F1X` encoding.
- **Stale-CAP trap:** debug builds appeared to change nothing — the renamed
  `target/010203040506.cap` wasn't refreshed by incremental builds. Workaround:
  `cp target/generated-jcdk/helloworld/javacard/helloworld.cap
  target/010203040506.cap` before every docker run; `mvn clean` always refreshes.
- Pinpointed: `hkdfExtract()` → `hmacKey.setKey(salt, 0, 32)`.

### Root cause A: HMACKey length semantics differ per runtime
On-card probe results (Oracle sim v26):
| variant | result |
|---|---|
| `buildKey(TYPE_HMAC, LENGTH_HMAC_SHA_256_BLOCK_64 /*=64*/)` → `getSize()` | 64 |
| `setKey(key, 0, 64/32/16)` on that key | **all ILLEGAL_VALUE** |
| 4-arg `buildKey(ALG_TYPE_HMAC, TYPE_HMAC*, 64, false)` | **NO_SUCH_ALGORITHM** |
| 3-arg `buildKey(TYPE_HMAC, (short)512, false)` + `setKey(…,0,32)` | **OK** |

→ Oracle reads the HMAC `buildKey` length as **bits** (64 → 8-byte capacity);
jCardSim reads it as **bytes** and accepted `setKey(…,32)` — our jCardSim-only
suite could never see this.

**Fix A:** dropped `HMACKey`/`Signature.ALG_HMAC_SHA_256`; HMAC-SHA-256 built
manually on `MessageDigest(ALG_SHA_256)` (RFC 2104): `fillPadBlock()` →
`K' ^ ipad/opad`, single-shot `doFinal` over pad‖msg (no multipart `update()`).
Keys here are always ≤ block → no long-key path needed. Verified: temporary
probe INS computed **RFC 4231 test vector 1** on the Oracle card = JCE value ✓.
(Intermediate state: multipart `update()` version already ran without crash on
Oracle and returned 6982 — so the remaining 6982 was NOT HMAC, see below.)

### Failure 2: EXCHANGE → SW 6982 (our own "security status" code)
- No `CryptoException` in `jcsl.log` anymore → our confirmation-token check
  failed, i.e. GCM layer.
- Root cause: **AEADCipher decrypt contract differs per runtime.**
  Oracle javadoc (authoritative, matches v26 behavior):
  1. `init(key, MODE_DECRYPT, iv, off, 12)` + `updateAAD(...)`
  2. `doFinal(ciphertextOnly)` → plaintext, n→n
  3. `verifyTag(wireTagBuf, off, len, requiredLen)` → **boolean**
  Passing `ct‖tag` (32 B) → Oracle decrypts 32 B as ciphertext →
  `dlen=32 ≠ 16` → our check → 6982. Exactly what we saw.
- **False alarm on the way:** first host probe said "jCardSim supports the spec
  model" — WRONG: the probe assembled `ct‖tag‖tag` (encrypt `doFinal` already
  returns ct‖tag!). Re-probe (Probe4, ctLen 4/8/16/24) gave the true matrix:

  | pattern | Oracle (spec) | jCardSim 3.0.6.0 |
  |---|---|---|
  | ENCRYPT `doFinal` | ct (retrieveTag separate) | **ct‖tag** (retrieveTag overwrites same bytes — harmless) |
  | `doFinal(ct)` + `verifyTag` | ✅ pt + true/false | ❌ CryptoException ("data too short" / "mac check failed") |
  | `doFinal(ct‖tag)` | ❌ dlen=ctLen+16, verifyTag false | ✅ pt; tamper → CryptoException; verifyTag after success → true |

  → **fundamentally incompatible** for a single decrypt pattern.

**Fix B (implemented): `gcmOpen()` — spec-first with fail-closed fallback.**
- Try spec form `doFinal(ct)` + `verifyTag` → on CryptoException, retry once
  with BC form `doFinal(ct‖tag)`; require `dlen == ctLen` in both.
- **Security argument:** on spec-compliant runtimes `doFinal` is n→n, so the BC
  retry sees `ctLen+16` bytes → `dlen != ctLen` → never returns true. A
  successful retry therefore implies a runtime with internal tag verification
  (jCardSim, test infra only). Spec-runtime tamper never even reaches the
  fallback (no exception; `verifyTag` false → wipe).
- Both call sites (`exchange()` confirmation token, `secretPing()` protected
  commands) now use `gcmOpen()`. secretPing AAD (header‖iv, contiguous since
  iv starts at OFFSET_CDATA) passed as one region. Encrypt paths unchanged
  (`doFinal`→ct, `retrieveTag`; works on both runtimes either way).
- Wire format unchanged → host client untouched.

## Final state (all verified)
- jCardSim: `mvn clean verify` → **12/12 green** (with gcmOpen + manual HMAC).
- Oracle sim v26: smoke harness → **18/18 PASS** (handshake, 3 ping round
  trips, replay rejected, tamper rejected + wiped, re-handshake recovery,
  deselect wipe).
- Debug instrumentation fully removed (applet probe INS 0x1F, harness probe,
  dbgStage) — grep-verified clean; `spotless:check` green.
- README: Limitations section rewritten (GCM decrypt-contract portability note
  + manual-HMAC rationale), new "Oracle simulator smoke test" section with the
  full docker command + `--applet`/`--create` notes.
- CI `.github/workflows/ci.yml` simulator job: `gp --install --applet` +
  `gp --create` + compiles/runs the smoke test (old flow would break on the
  two-applet CAP).
- All **uncommitted**; user reviews first, then multiple thematic commits.
  Old applet backup: `/tmp/SecureChannelApplet.java.bak` (historical).

## Unfinished tasks / TODO
- Review by user → decide commit scope/granularity → commit(s) (ask! never
  push). Then update `.opencode/TODOs.md`.
- Investigate: jcdk rename step to `<appletAID>.cap` not refreshing on
  incremental builds (stale-CAP trap; `mvn clean` masks it).
- Later (pre-existing TODOs): static ECDSA card authentication (closes MITM
  gap), large-payload APDU chaining.

## Problems and solutions
- Stale CAP → manual `cp` from `target/generated-jcdk/...` before docker runs.
- HMACKey bits-vs-bytes → manual HMAC via MessageDigest (Fix A).
- GCM decrypt-contract divergence → `gcmOpen()` spec-first + fail-closed
  BC fallback (Fix B); probe assembly bug (`ct‖tag‖tag`) nearly mislead us —
  double-check probe inputs when crypto semantics are in question!
- Simulator blocks commands to an applet after uncaught exception → encode
  debug state in the SW of the failing command instead.
- pyscard in the container raced the reader → drive tests from the Java harness.

## Constraints / Pitfalls
- Oracle sim `jcsl.log`: `grp:japi` logs `getInstance`/`buildKey` but not
  runtime crypto calls (init/doFinal/sign) — can't trace primitives via log.
- `gp --install` multi-applet → needs `--applet <AID>`; second applet via
  `gp --create` (reload refused 0x6985). Affects CI + any install docs.
- jCardSim ENCRYPT `doFinal` returns **ct‖tag** (24 for 8B pt); real spec says
  ct only + `retrieveTag`. Our seal path is compatible with both (retrieveTag
  rewrites the identical tag at the identical offset).
- CryptoException reasons: ILLEGAL_VALUE=1, UNINITIALIZED_KEY=2,
  NO_SUCH_ALGORITHM=3, INVALID_USE/INIT=4/5.
- `javacard.security.SymmetricKey` not visible in the api_classic build used
  here → type applet helper params as `AESKey`.

## Key decisions
- Manual HMAC-SHA-256 via `MessageDigest` instead of `HMACKey`/`Signature` —
  sidesteps runtime length-semantics divergence; wire protocol unchanged.
- GCM: card follows the **Java Card spec** (`doFinal(ct)` + `verifyTag`), the
  BC-style retry exists purely for jCardSim CI and is provably inert on
  spec-compliant cards.
- Smoke test lives in `simulator/` as dependency-free single-file Java
  (compiled inside the container; no Maven impact). CI mounts it and runs it.

## Next steps
1. User review → commit plan (multiple commits, scope TBD) → commit after ask.
2. Update `.opencode/TODOs.md` post-commit.
3. Follow-ups: card authentication (ECDSA static key), APDU chaining;
   optional: fix/understand jcdk rename staleness.
