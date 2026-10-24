# Building offline with `lib/`

Jars put in this directory are used in preference to Maven Central (it is the
first repository in `build.gradle`), so that Orchid can be built where the
Gradle repositories cannot be reached.

## What needs what

The **library itself has no dependencies**: `gradle jar` and `gradle fatJar`
need no jars here.  Only the tests, the demo programs and the optional XML-RPC
transport do:

| Part | Gradle task | Jars |
|---|---|---|
| Library (`src/main`) | `jar`, `fatJar` | none |
| Tests (`test`) | `test`, `build` | `junit-4.13.2.jar`, `hamcrest-core-1.3.jar`, `easymock-5.4.0.jar`, `objenesis-3.4.jar`, `byte-buddy-1.14.18.jar`, `asm-9.7.jar` |
| Demo programs (`src/demo`) | `demoJar` (part of `build`), `runDemo` | `commons-io-2.18.0.jar`, `jsoup-1.18.3.jar` |
| XML-RPC transport (`src/xmlrpc`) | `xmlrpcJar` | `xmlrpc-common-3.1.3.jar`, `xmlrpc-client-3.1.3.jar`, `ws-commons-util-1.0.2.jar` |

So `gradle build` needs the jars of the tests and the demo programs.

## Naming the files

Name each jar `<artifactId>-<version>.jar`, with the version that
`build.gradle` asks for, as in the table.  Gradle uses only the jars that
`build.gradle` declares; other jars here are ignored.

A jar taken from here comes without its POM, so Gradle cannot learn from it
which libraries it needs in turn.  `build.gradle` therefore declares those
too (hamcrest-core for JUnit; Objenesis, Byte Buddy and ASM for EasyMock;
ws-commons-util for Apache XML-RPC), and they are in the table.  When a
library is updated in `build.gradle`, check its POM for changes in its own
dependencies and update the table.

The XML-RPC transport does not use Apache XML-RPC's Commons HttpClient
transport, so `commons-httpclient` and its dependencies are not needed.

## Gradle itself

The Gradle wrapper (`./gradlew`) downloads Gradle the first time it runs.
Offline, use a Gradle 8.x installed on the machine:

```
gradle --offline build
```

The jars here are ignored by git (`*.jar` in `.gitignore`).
