# javacard-maven-helloworld

A minimal JavaCard Hello World applet built with Maven.

This repository retains the Maven example's Git history from
[docker-javacard](https://github.com/andreas-mausch/docker-javacard).

# Requirements

This project uses two separate Java compilers:

- **Main sources (applet code)** — compiled against Java 1.1 with a **JDK 8** `javac`, because recent JDKs (17+) reject the old `-target 1.1` option that JavaCards require. You must specify the path to your JDK 8 `javac` via `-Djava.compiler.main.path`.
- **Test sources** — compiled using your JDK from `$JAVA_HOME` / `$PATH`.

Use **Maven 3.9 or newer** with your installed **JDK 25 or newer**;
3.9.12 or newer avoids some deprecation warnings on JDK 25.
Only the applet compilation step requires a separate JDK 8 compiler.

> **Note:** If you increase the target version beyond 1.1, the resulting `.cap` file may not run on all JavaCards.

# Configuration

`pom.xml` contains project-specific settings, plugins and dependencies. It inherits
from `de.neonew.build:javacard-parent:1.5.0`, which extends the Java parent from
[my-maven-setup](https://github.com/andreas-mausch/my-maven-setup).

You **must** define these properties in your `pom.xml`:
- `<applet.id>` — JavaCard AID (e.g. `01:02:03:04:05:06`)
- `<main.class>` — fully qualified applet class (e.g. `helloworld.HelloWorldApplet`)

`<applet.version>` is automatically derived from `<version>` by stripping any
qualifier (e.g. `1.0-SNAPSHOT` → `1.0`). You can still override it explicitly.

# AIDs

JavaCard distinguishes three AIDs. In this project they are:

| AID | Value | Where it comes from |
|---|---|---|
| Package AID | `0102030405` | Derived from the first 5 bytes of `<applet.id>`; exposed as the `${package.id}` property |
| Applet AID | `010203040506` | Your `<applet.id>`; stored in the CAP's applet component |
| Instance AID | `010203040506` | Assigned at install time; a default `gp --install` (and jCardSim's `installApplet`) uses the applet AID |
| Second applet | `010203040507` | `<applet.id.secure>` — `SecureChannelApplet`, same package and CAP (see "Secure channel applet") |

`SELECT` always targets the *instance* AID — `010203040506` here:

```text
00 A4 04 00 06 010203040506 → 9000
```

Integration tests receive all values as system properties injected by the parent:
`javacard.applet.id`, `javacard.applet.id.nocolons`, `javacard.package.id` and
`javacard.package.id.nocolons` — see `HelloWorldAppletTest`.

See [AIDs](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.5.0/README-javacard.md#aids)
for the background on all three.

# Secure channel applet (ECDH + HKDF + AES-256-GCM)

`helloworld.SecureChannelApplet` (instance AID `010203040507`, same CAP as
`HelloWorldApplet`) establishes an encrypted, integrity-protected application
channel between a phone app and the card — applet-level, independent of the
GlobalPlatform SCP02 management channel.

## Protocol v1

All commands use `CLA = 0x80`. Curve is secp256r1 (`P-256`), domain parameters
pinned in the applet.

| INS | Name | Direction | Payload |
|---|---|---|---|
| `0x10` | INIT | → card | — |
| | | ← card | `Q_card (65B) \|\| N_card (16B)` |
| `0x12` | EXCHANGE | → card | `Q_peer (65B) \|\| N_peer (16B) \|\| iv (12B) \|\| ct (16B) \|\| tag (16B)` |
| | | ← card | `iv (12B) \|\| ct (16B) \|\| tag (16B)` |
| `0xB0` | SECRET_PING | → card | `iv (12B) \|\| ct \|\| tag (16B)` (echo demo for protected commands) |

Key derivation after both nonces are known:

```
Z      = ECDH(d_card, Q_peer)                    (KeyAgreement ALG_EC_SVDP_DH_PLAIN)
salt   = N_card || N_peer
PRK    = HKDF-Extract(salt, Z)                   (HMAC-SHA-256)
K_conf = HKDF-Expand(PRK, "SCv1-conf")[0..16)    AES-128, handshake tokens only
K_msg  = HKDF-Expand(PRK, "SCv1-msg")[0..32)     AES-256, session messages
```

EXCHANGE carries a key-confirmation token — AES-GCM under `K_conf` over the
transcript `Q_card || Q_peer || N_card || N_peer || dir` as AAD — and the card
answers with its own token (direction byte flipped). On success the session is
active; the keys live in transient `AESKey` objects.

Protected commands use `K_msg`. The 12-byte IV is `prefix (4B) || seq (8B,
big-endian, strictly increasing)` with per-direction prefixes taken from the
session nonces; the IV and the APDU header are bound into the GCM AAD, which
gives replay and reordering protection. `0x6982
SECURITY_STATUS_NOT_SATISFIED` is returned when: no session is active, a
command arrives without/before its sequence, or integrity fails. **Any
integrity failure wipes the session** — the phone must redo INIT/EXCHANGE.
Deselecting the applet also wipes the session (transient keys and arrays).

## Protected commands for your own instructions

`SECRET_PING` is a template: call `requireSession()` first, then reuse the
AAD/IV scheme from `secretPing()` (or lift its open/seal parts into helpers)
for each instruction you want to guard. Non-protected instructions (like
`INIT`/`EXCHANGE`) stay open by design.

## Install-time capability self test

`Applet.install` probes every primitive this applet needs **before**
`register()`, so a card that lacks one fails the GP INSTALL instead of
registering a half-usable applet. The applet throws `ISOException` with a
vendor status word `0x9F00 | bitmask` of missing pieces:

| Bit | Missing primitive |
|---|---|
| `0x01` | `MessageDigest` SHA-256 |
| `0x02` | `RandomData` secure random |
| `0x04` | EC FP 256-bit keys |
| `0x08` | `KeyAgreement` `ALG_EC_SVDP_DH_PLAIN` |
| `0x10` | AES `*_TRANSIENT_DESELECT` keys (128 + 256) |
| `0x20` | `AEADCipher` `ALG_AES_GCM` |
| `0x40` | GCM functional test failed |

The functional GCM test (`0x40`) seals a known plaintext, opens it back
through the same `gcmOpen()` code path the session later uses and verifies
that a flipped ciphertext byte is rejected — runtimes that advertise GCM but
implement it inconsistently fail at install, too.

How the failure surfaces is runtime-dependent: on the Oracle simulator v26
the GP tool reports the generic `INSTALL … failed: 0x6A80` while
`/var/log/jcsl.log` shows the exact reason
(`ISOException (reason=0x9F04)` = EC FP-256 keys missing). On real hardware
the SW mapping depends on the card runtime and loader.

## Limitations (read before production use!)

- **No entity authentication.** Both ECDH keys are ephemeral, so an active
  network attacker can run two handshakes (MITM). Mitigation options: pin a
  static card key and sign the handshake (`Signature ALG_ECDSA_SHA_256`), or
  provision per-card secrets out-of-band.
- GCM support is optional in Java Card 3.0.5 — probe it on your target card,
  e.g. with a tiny self-test INS calling
  `AEADCipher.getInstance(AEADCipher.ALG_AES_GCM, false)`. The AEADCipher
  *decrypt* contract also varies between runtimes: the spec (and the Oracle
  simulator / real cards) uses `doFinal(ciphertext)` -> plaintext followed by
  `verifyTag(wireTag)` -> boolean, while jCardSim implements the JCE/BC-style
  `doFinal(ct || tag)` with internal verification. `gcmOpen()` tries the spec
  form first and retries the BC form only after a `CryptoException`; on a
  spec-compliant runtime that fallback can never authenticate a forged
  message (their `doFinal` is n -> n, so the retry sees `ctLen + 16` bytes and
  is rejected). Verified end-to-end on the Oracle simulator v26 and jCardSim.
- HMAC-SHA-256 is built on `MessageDigest.ALG_SHA_256` (RFC 2104, one-shot)
  instead of `Signature.ALG_HMAC_SHA_256` + `HMACKey`: runtimes disagree on
  the unit of `KeyBuilder.buildKey(..., TYPE_HMAC, len)` (the Oracle simulator
  reads it as *bits*, jCardSim as *bytes*, which rejects `setKey` of a 32-byte
  key), and the 4-arg `buildKey` variant with `ALG_TYPE_HMAC` is not supported
  there at all. The manual construction sidesteps this entirely (all keys here
  are ≤ block size, so no long-key hashing path is needed).
- `KeyPair.genKeyPair()` on INIT can take hundreds of ms on real silicon.

## Build plumbing for two applets in one CAP

The jcdk plugin normally converts exactly one applet. When
`target/generated-jcdk/jcdk.config` already exists it is passed to the
converter verbatim, so `src/main/jcdk/jcdk.config` (a filtered Maven resource,
see the `generate-jcdk-config` execution) declares both `-applet` entries.
Keep the `jcdk.aid.*` properties in `pom.xml` in sync with
`<applet.id>` / `<applet.id.secure>`.

`SecureChannelClient` (test scope) is a plain-JCE reference implementation of
the phone side — Android can use the same primitives.

# Build

This example uses the **JavaCard 3.0.5 SDK (`jc305u4_kit`)**. SDKs are
available from [oracle_javacard_sdks](https://github.com/martinpaljak/oracle_javacard_sdks).
The SDK is not bundled with this project and has its own license.

Before the first build, install the JavaCard SDK's `api_classic.jar` into your local
Maven repository. This is a one-time step:

```bash
mvn install:install-file \
  -Dfile=/path/to/jc305u4_kit/lib/api_classic.jar \
  -DgroupId=com.oracle.javacard -DartifactId=api-classic \
  -Dversion=3.0.5 -Dpackaging=jar
```

Then build the project:

```bash
mvn clean verify \
  -Djava.compiler.main.path=/path/to/jdk8/bin/javac \
  -Djavacard.sdk.path=/path/to/jc305u4_kit
```

Both path arguments are **required**. They select the JDK 8 compiler and JavaCard SDK.

To avoid passing it every time, persist it in `.mvn/maven.config`:

```bash
mkdir -p .mvn
cat > .mvn/maven.config <<'EOF'
-Djava.compiler.main.path=/path/to/jdk8/bin/javac
-Djavacard.sdk.path=/path/to/jc305u4_kit
EOF
```

The build produces `target/010203040506.cap` and
`target/javacard-applet-1.0-SNAPSHOT.jar`. Add `-Psize-optimization` to enable
ProGuard, or `-Pcoverage` for coverage reports in `target/reports/coverage`.

The commands below assume both local paths have been configured in
`.mvn/maven.config`. Otherwise, append the two `-D` path arguments to each build
command. This local configuration file is ignored by Git.

# Testing and reports

`mvn clean verify` runs all tests. Integration tests live under
`src/test-integration/java` in a package containing `.integration.`.
Surefire excludes these tests; Failsafe runs them during `verify`.

This example currently has twelve integration tests (three for Hello World,
nine for the secure channel) and no separate unit tests.
Results are written to `target/failsafe-reports/`, with an HTML report at
`target/reports/tests-integration.html`. A warning about missing unit-test report
input is expected because there are no unit tests.

## Oracle simulator smoke test

`simulator/OracleSimulatorSmokeTest.java` exercises the built CAP end-to-end on
the real Oracle Java Card simulator (v26.0) inside a
[docker-javacard](https://github.com/andreas-mausch/docker-javacard) container:
selects both applets, runs a full handshake, protected round trips, replay and
tamper rejection and checks that deselecting wipes the session. It is a
dependency-free single-file program (`javax.smartcardio` + JCE) that is compiled
inside the container:

```bash
docker run --rm \
  --volume "$PWD/target/010203040506.cap:/applet/helloworld.cap:ro" \
  --volume "$PWD/simulator:/simulator:ro" \
  --env GLOBALPLATFORMPRO_VERSION=25.10.20 \
  --env START_JAVACARD_SIMULATOR=y docker-javacard bash -ec '
    gp() { java -jar "/javacard/gp-v${GLOBALPLATFORMPRO_VERSION}.jar" "$@"; }
    unset GP_KEY GP_KEY_ENC GP_KEY_MAC GP_KEY_DEK
    gp --install ./helloworld.cap --applet 010203040506
    gp --create 010203040507 --package 0102030405 --applet 010203040507
    javac -d /tmp/smoke /simulator/OracleSimulatorSmokeTest.java
    java -cp /tmp/smoke OracleSimulatorSmokeTest'
```

Two notes on installing a CAP that contains two applets: `gp --install`
refuses it without `--applet <AID>` (the AID, not the class name), and the
second instance must be created with `gp --create` — a second `gp --install`
tries to reload the package, which the simulator rejects with `0x6985`.

# Linting and formatting

Check formatting without changing files:

```bash
mvn -Plinting clean verify
```

Apply formatting:

```bash
mvn -Plinting spotless:apply
```

Spotless formats Java sources and `pom.xml` using the parent rules, including
two-space indentation. Wildcard imports are forbidden and must be replaced
manually if reported.

Run these checks automatically before every commit by enabling the included
pre-commit hook once per clone:

```bash
git config core.hooksPath githooks
```

# Coverage and size optimization

```bash
mvn -Pcoverage clean verify
mvn -Psize-optimization clean verify
```

The HTML coverage report is `target/reports/coverage.html`; XML and CSV data
are written to `target/reports/coverage/`. Size optimization
uses ProGuard before JCDK builds the `.cap`; it is disabled by default.
Profiles can be combined, for example `-Plinting,coverage,size-optimization`.

# Software Bill of Materials (SBOM)

The parent provides two SBOM generators through the `sbom` profile:

- **CycloneDX** (`org.cyclonedx:cyclonedx-maven-plugin`) — security-focused, excludes test dependencies.
  Output: `target/javacard-applet-1.0-SNAPSHOT.sbom.cyclonedx.json`
- **SPDX** (`org.spdx:spdx-maven-plugin`) — license/compliance-focused, includes all scopes.
  Output: `target/javacard-applet-1.0-SNAPSHOT.sbom.spdx.json`

Both run during `mvn package` and produce JSON. Activate them with the `sbom` profile:

```bash
mvn -Psbom clean package
```

# Vulnerability scanning

Install [Grype](https://github.com/anchore/grype) and ensure `grype` is on your
`PATH`. Generate an SBOM and scan dependencies:

```bash
mvn -Psbom,vulnerability-report clean verify
```

Open `target/reports/vulnerabilities-dependencies.html` for the results.
The scan uses the CycloneDX SBOM, which excludes test dependencies such as
jCardSim and JUnit. The SPDX SBOM includes test dependencies but is not used
by this scan.
The scan requires access to Grype's vulnerability database. This profile
generates a report; a successful build does not imply there are no findings.

# License check

Check dependency licenses against the parent's allowlist:

```bash
mvn -Plicense-check clean verify
```

The build fails if any dependency has a license not in the allowlist or is
missing license metadata.

License aliases, the allowlist and the Oracle JavaCard SDK metadata override are
provided by the parents and shared build configuration in `my-maven-setup`.
The Oracle SDK is explicitly allowed; this does not make it FOSS.
Reports are written to `target/reports/THIRD-PARTY.txt` and
`target/reports/dependency-licenses.html`.

# Run single test

```bash
mvn test-compile failsafe:integration-test failsafe:verify \
  -Dit.test=HelloWorldAppletTest#testPing
```

# Signing

Artifacts can be signed with GPG using the `sign` profile. You must specify the key fingerprint via `-Dgpg.key`:

```bash
mvn -Psign -Dgpg.key=1234567890ABCDEF1234567890ABCDEF12345678 clean verify
```

Find your key fingerprint with `gpg --list-secret-keys`.

## Verify a signed release

Each release artifact (`.jar`, `.cap`, `.pom`) has a matching `.asc` signature file. To verify it's from the correct author:

```bash
gpg --verify target/010203040506.cap.asc target/010203040506.cap
```

You need the author's public key imported. It can be downloaded from a key server:

```bash
gpg --keyserver keys.openpgp.org --recv-key 1234567890ABCDEF1234567890ABCDEF12345678
```

Replace the key ID with the one used for signing.

# More parent features and troubleshooting

See [JavaCard setup](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.5.0/README-javacard.md)
and [shared features](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.5.0/Features.md)
for compiler warnings, optional vulnerability scanning with Grype, pre-commit
hooks, and additional build features.

If parent resolution fails, check the parent coordinates and your Maven settings.
If `api-classic` cannot be resolved, install the SDK JAR as
shown above. If compilation or CAP conversion fails, check both local paths and
ensure the applet compiler is from JDK 8.

# Maintenance

Update dependency versions:

```bash
mvn versions:display-dependency-updates
mvn versions:display-plugin-updates
mvn versions:display-property-updates -DincludeParent
```

# Continuous integration

`.github/workflows/ci.yml` builds on pushes to all branches, published GitHub
releases, and manual runs. Pull-request builds are disabled for now.
It runs linting, tests, coverage, size optimization, SBOM generation, license
checks, vulnerability reports, and signing. It verifies signatures and uploads
the CAP, JAR, SBOMs, public signing key, and reports. High or critical findings
in the production CycloneDX SBOM fail CI.

Signing uses an isolated temporary GPG directory. Set
`OPENPGP_KEY_BIP39_MNEMONIC` for signing published releases; release builds fail
if it is missing. All runs use `bip39key`. Pushes and manual runs
use the public test mnemonic
`beef beef beef beef beef beef beef beef beef beef beef beef` and do not receive
the signing secret. This fixed test key is publicly reproducible;
its signatures are not trusted release signatures.

The additional Oracle simulator job is opt-in: start the workflow manually with
`run_simulator` enabled and set `ORACLE_JAVACARD_SIMULATOR_URL` to the download
URL for the v26.0 simulator archive used by `docker-javacard`. The job builds
the Docker environment from a pinned commit, installs both applet instances
(`gp --install --applet` + `gp --create`, see the smoke test section) and runs
`simulator/OracleSimulatorSmokeTest.java`. The test explicitly checks the final
response for `48656C6C6F9000` (Hello and success).
The simulator download is checksum-verified.

# License

This project is licensed under the [Apache License 2.0](LICENSE).
The Oracle JavaCard SDK and third-party dependencies retain their own licenses.
