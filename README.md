# javacard-maven-helloworld

A minimal JavaCard Hello World applet built with Maven.

This repository retains the Maven example's Git history from
[docker-javacard](https://github.com/andreas-mausch/docker-javacard).

# Requirements

This project uses two separate Java compilers:

- **Main sources (applet code)** — compiled against Java 1.1 with a **JDK 8** `javac`, because recent JDKs (17+) reject the old `-target 1.1` option that JavaCards require. You must specify the path to your JDK 8 `javac` via `-Djava.compiler.main.path`.
- **Test sources** — compiled using your JDK from `$JAVA_HOME` / `$PATH`.

Use **Maven 3.9.16 or newer** with your installed **JDK 25 or newer**;
you do not need to install JDK 25 specifically if you already use Java 27.
Only the applet compilation step requires a separate JDK 8 compiler.

> **Note:** If you increase the target version beyond 1.1, the resulting `.cap` file may not run on all JavaCards.

# Configuration

`pom.xml` contains project-specific settings, plugins and dependencies. It inherits
from `de.neonew:javacard-parent:1.1.0`, which extends the Java parent from
[my-maven-setup](https://github.com/andreas-mausch/my-maven-setup).

The parents and shared build configuration are published in GitHub Packages.
Before building, configure the repository and credentials in `~/.m2/settings.xml`
as described in [Configure GitHub Packages](https://github.com/andreas-mausch/my-maven-setup#configure-github-packages).
A GitHub token with `read:packages` permission is required. No credentials belong
in this repository.

You **must** define these properties in your `pom.xml`:
- `<applet.id>` — JavaCard AID (e.g. `01:02:03:04:05:06`)
- `<main.class>` — fully qualified applet class (e.g. `helloworld.HelloWorldApplet`)

`<applet.version>` is automatically derived from `<version>` by stripping any
qualifier (e.g. `1.0-SNAPSHOT` → `1.0`). You can still override it explicitly.

# Build

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

# Software Bill of Materials (SBOM)

The project includes two SBOM generators (opt-in via `pom.xml`):

- **CycloneDX** (`org.cyclonedx:cyclonedx-maven-plugin`) — security-focused, excludes test dependencies.
  Output: `target/bom.json`
- **SPDX** (`org.spdx:spdx-maven-plugin`) — license/compliance-focused, includes all scopes.
  Output: `target/site/helloworld_javacard-applet-1.0-SNAPSHOT.spdx.json`

Both run during `mvn package` and produce JSON. Activate them with the `sbom` profile:

```bash
mvn clean package -Psbom
```

# Shaded (fat) .jar

The project can produce a shaded (fat) JAR with the `maven-shade-plugin`.
Activate it by adding the `shade` and `git-commit-id` plugins:

```xml
<plugin>
  <groupId>io.github.git-commit-id</groupId>
  <artifactId>git-commit-id-maven-plugin</artifactId>
</plugin>
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-shade-plugin</artifactId>
</plugin>
```

Set `<mainClass>` via a `ManifestResourceTransformer` in your own configuration
if you need an executable JAR.

# License check

Enforce that all dependencies use only FOSS licenses with the `license-check`
profile:

```bash
mvn clean verify -Plicense-check
```

The build fails if any dependency has a license not in the FOSS allowlist or is
missing license metadata.

License aliases, the allowlist and the Oracle JavaCard SDK metadata override are
provided by the parents and shared build configuration in `my-maven-setup`.

# Run single test

```bash
mvn test [-Dtest=TestClass#testMethod]
mvn failsafe:integration-test [-Dit.test=TestClass#testMethod]
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
gpg --verify javacard-applet-1.0.asc javacard-applet-1.0.cap
```

You need the author's public key imported. It can be downloaded from a key server:

```bash
gpg --keyserver keys.openpgp.org --recv-key 1234567890ABCDEF1234567890ABCDEF12345678
```

Replace the key ID with the one used for signing.

# Maintenance

Update dependency versions:

```bash
mvn versions:display-dependency-updates
mvn versions:display-plugin-updates
mvn versions:display-property-updates -DincludeParent
```
