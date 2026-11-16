# Session 2026-11-16 — Cipher suites via mandatory install parameter (SC v1.1)

## Goals
- Make the secure channel usable on the real card, which lacks AES-GCM
  (probe verdict from earlier today: only bit 0x20 missing — SHA-256, RNG,
  EC P-256, ECDH-PLAIN, AES transient keys all present).
- Hard requirement: the cipher suite **must** be given via the GP
  install parameter — no default, no runtime fallback, so nobody can ever
  silently slide onto a "worse" algorithm unnoticed.
- → **Achieved:** suite `01` = AES-256-GCM, suite `02` = AES-256-CBC
  (ISO9797-M2) + HMAC-SHA-256 Encrypt-then-MAC; five commits
  (`51b070b`…`c385ecc`), 18/18 jCardSim + 31/31 Oracle simulator.

## Preferences
- Ask before git commit; never push (neonew pushes personally).
- Session summaries in `.opencode/session-*.md`; TODOs in `.opencode/TODOs.md`
  (mark done only after commits — done at end of this session).
- Fine-grained conventional commits, bodies wrapped at 72 chars.
- "Schmal, aber sicher" still holds; suite 02 is explicitly documented as
  the fallback, GCM stays the preferred suite.

## Key decisions
- **Suite fixed at instance creation** via one install-param byte
  (`gp --create … --params 01|02`). Missing → SW `0x9E01`, unknown →
  `0x9E02`. Multiple instances of the same class with different params can
  coexist (`…0507` GCM, `…0508` CBC+HMAC).
- Suite byte joins the handshake transcript
  (`Q_card||Q_peer||N_card||N_peer||suite||dir`) → keys/tokens/ciphertexts
  are suite-bound; cross-suite confusion impossible. INIT echoes the suite;
  the host client aborts on mismatch.
- Suite 02 construction: AES-256-CBC + M2 padding, **Encrypt-then-MAC**
  over `aad||iv||ct`, HMAC-SHA-256 truncated to 16 B (same wire shape as
  GCM tags everywhere), verified constant-time **before** decrypting — no
  padding oracle by construction.
- MAC keys are **raw transient byte[]**, not HMACKey/Signature — reuses the
  established MessageDigest-based HMAC (HMACKey length semantics are the
  known portability trap).
- HKDF labels: suite 01 keeps `SCv1-conf`/`SCv1-msg` (wire-compatible with
  the old spike); suite 02 uses `SCv2-conf`/`SCv2-confmac`/`SCv2-msg`/
  `SCv2-mac`.
- Probe is suite-aware: bits 0x20/0x40 now mean "chosen suite's cipher
  unavailable / functional KAT failed"; CBC KAT runs the production
  `sealCbcHmac()`/`openCbcHmac()` path incl. tamper rejection.
- Response AAD asymmetry documented: GCM `INS||iv`, CBC just `INS` (iv is
  inside the MAC input).

## Progress / Done
- `SecureChannelApplet.java`: install-param parsing (`[len][aid][1][caps]
  [len][suite]`), per-suite constructor (conditional GCM/CBC allocation,
  decBuf 256/384), static `sealGcm`/`sealCbcHmac`/`openCbcHmac` + instance
  dispatchers `seal()`/`openMsg()`, generalized HMAC core
  (`hmacSha256(md, ws, inner, …)` + `hmacFromWorkspace`), suite-aware
  probe incl. `probeCbcHmac()`, INIT echo, wipe of MAC key buffers.
  → `51b070b`
- `SecureChannelClient` + `SecureChannelAppletTest`: suite-aware client
  (manual M2 pad/unpad), tests for both suites (handshake+5×ping, tamper→
  wipe, replay), suite echo, mismatch refusal, bad-param install rejection
  (15 SC tests, 18 total). → `9001525`
- `OracleSimulatorSmokeTest`: scenario per suite instance; **skips missing
  instances** → usable on the real card with only one suite installed.
  → `da850eb`
- CI creates `…0507`/`--params 01` + `…0508`/`--params 02` (`--applet` is
  always the class AID!). → `f838be1`
- README: suites section, SW table (`0x9E01`/`0x9E02`, renamed bits),
  updated recipes. → `c385ecc`

## Problems and solutions
- **gp flag:** it's `--params <hex>` (checked via `gp --help`).
- **`0x6A88` on `gp --create 010203040508 --applet 010203040508`:**
  `--applet` names the applet *class* AID in the CAP (`…0507`); the first
  positional arg is the free-form *instance* AID.
- **Host MAC input got tangled mid-rewrite** (`aad||iv||ct` assembled
  inconsistently at call sites): fixed by one `seal/open(aad, iv, ctAndTag)`
  contract with iv always explicit. Symptom was `AEADBadTag` in the GCM
  response open only — the card binds `INS||iv`, the rewritten client passed
  just `INS`.
- **Pre-commit hook rejected the first commit:** I had run
  `mvn spotless:apply` **without `-Plinting`** — a silent no-op. The hook
  uses `--activate-profiles linting`; README says so. Re-applied, re-verified
  everything, committed.
- **CBC response IV tail bytes:** scratch[13..17) could hold token-phase
  random; now explicitly zeroed for suite 02 (determinism, not security).

## Constraints / pitfalls
- jCardSim passes the bArray through unchanged — test helper must write the
  full GP layout, an `[len][aid]`-only array would read out of bounds.
- decBuf is the HMAC workspace for suite 02: 384 B = 64 pad + 244 max MAC
  input (worst-case short APDU) + 32 tail (inner digest + MAC output). The
  KAT wire buffer lives at the ws tail to never overlap pad||msg.
- `Util.arrayCompare` is the constant-time compare (JC 3.0.5 requirement).
- jCardSim `Cipher.ALG_AES_CBC_ISO9797_M2` works (BC-backed); real card's
  support for M2 is **untested** — the probe will tell (bit 0x20/0x40).
- Smoke harness stays JDK-only: M2 padding by hand, `AES/CBC/NoPadding` +
  `Mac HmacSHA256` (no BouncyCastle inside the container).

## Next steps
- neonew: rebuild + deploy to the **real card** with `--params 02`; expected:
  install succeeds (or probe reports CBC missing with 0x9F20/0x9F40),
  `--params 01` must keep failing `0x9F20` — proof the fail-closed design
  holds on hardware.
- Real-card command sequence (old CAP on card):
  `gp --delete 010203040506` → `gp --delete --package 0102030405` →
  `gp --install … --applet 010203040506` → `gp --create 010203040508
  --package 0102030405 --applet 010203040507 --params 02`.
- neonew pushes `spike/secure-channel`; PR/evaluation later.
- Open follow-ups live in `.opencode/TODOs.md` (card authentication/MITM,
  chaining/status INS, jcdk stale-CAP rename).
