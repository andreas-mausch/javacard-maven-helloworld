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
from `de.neonew.build:javacard-parent:1.4.0`, which extends the Java parent from
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

`SELECT` always targets the *instance* AID — `010203040506` here:

```text
00 A4 04 00 06 010203040506 → 9000
```

Integration tests receive all values as system properties injected by the parent:
`javacard.applet.id`, `javacard.applet.id.nocolons`, `javacard.package.id` and
`javacard.package.id.nocolons` — see `HelloWorldAppletTest`.

See [AIDs](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.4.0/README-javacard.md#aids)
for the background on all three.

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

This example currently has three integration tests and no separate unit tests.
Results are written to `target/failsafe-reports/`, with an HTML report at
`target/reports/tests-integration.html`. A warning about missing unit-test report
input is expected because there are no unit tests.

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

See [JavaCard setup](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.4.0/README-javacard.md)
and [shared features](https://github.com/andreas-mausch/my-maven-setup/blob/javacard-parent-v1.4.0/Features.md)
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
the Docker environment from a pinned commit, installs the CAP, and runs
`hello.gpshell`. Its download is checksum-verified.

# License

This project is licensed under the [Apache License 2.0](LICENSE).
The Oracle JavaCard SDK and third-party dependencies retain their own licenses.
