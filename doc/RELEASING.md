# Releasing Orchid

Releases go to GitHub (signed tag, jars, `SHA256SUMS`) and to Maven Central
as `org.mhatta:orchid`.  Everything is built from the release tag: the
version comes from `git describe`, and a build that is not exactly a tag
(`2.4.0-3-g1234abcd`, `-dirty`) refuses to make a Maven Central bundle.

## One-time setup

1. **Central Portal account and namespace.**  Sign up at
   <https://central.sonatype.com>, add the namespace `org.mhatta`, and prove
   ownership of mhatta.org with the DNS TXT record the Portal shows (at the
   DNS provider that serves the domain's NS records).  Keep the record.
2. **User token.**  In the Portal: Account, Generate User Token.  Put it in
   `~/.gradle/gradle.properties` (never in the repository):

   ```properties
   mavenCentralUsername=<token user name>
   mavenCentralPassword=<token password>
   signing.gnupg.keyName=<OpenPGP key id or fingerprint>
   ```

3. **Signing key.**  The build signs with the local `gpg` and its agent
   (`signing.gnupg.keyName` above), so the private key never leaves the
   keyring; no key file is exported.  The public key must be on a key server
   that Central searches, for example:

   ```sh
   gpg --keyserver keyserver.ubuntu.com --send-keys <key id>
   ```

   Use the same key as for the release tags.  Do not put that key into CI.

## Making a release

```sh
# 1. Tag the release (signed) and push it.
git tag -s v2.4.0 -m "Orchid 2.4.0"
git push origin master v2.4.0

# 2. Build from the tag, with no local changes, using JDK 21.
git checkout v2.4.0
./gradlew clean check fatJar centralBundle

# 3. Upload the bundle; the script waits until the Portal has validated it.
tools/central-upload.sh build/distributions/orchid-2.4.0-bundle.zip
```

4. Look at the deployment at <https://central.sonatype.com/publishing/deployments>
   (files, POM, signatures) and press **Publish**.  It appears on
   <https://repo1.maven.org/maven2/org/mhatta/orchid/> within about half an
   hour.  **A published version can never be changed or removed**: if
   something is wrong, drop the deployment instead of publishing it, and
   make a new version.
5. On GitHub, create the release from the tag with
   `build/libs/Orchid-2.4.0.jar`, `build/libs/Orchid-2.4.0-all.jar` and
   `SHA256SUMS` (`cd build/libs && sha256sum Orchid-2.4.0.jar Orchid-2.4.0-all.jar > SHA256SUMS`).

## Reproducible builds

The jars are reproducible: the same tag built with the same JDK major
version gives byte-for-byte identical files, wherever and whenever it is
built.  To check a release:

```sh
git clone https://github.com/mhatta/Orchid && cd Orchid
git checkout v2.4.0
./gradlew jar sourcesJar javadocJar
sha256sum build/libs/Orchid-2.4.0.jar
# compare with the published jar
curl -sO https://repo1.maven.org/maven2/org/mhatta/orchid/2.4.0/orchid-2.4.0.jar
sha256sum orchid-2.4.0.jar
```

The class files depend on the javac version, so use the JDK the release
was built with (JDK 21 for the 2.x releases).
