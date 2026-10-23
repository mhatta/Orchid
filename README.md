Orchid
======

Orchid is a Tor client implementation and library written in pure Java.  Orchid's strength is that it can be used to Tor-ify Java and JVM applications with near transparency.

It was written from the Tor specification documents, which are available [here](https://www.torproject.org/docs/documentation.html.en#DesignDoc).

Orchid targets Java 8 bytecode and builds and runs on current JDKs (tested with JDK 21).

Orchid speaks the current Tor protocols: link protocols 4 and 5, ntor circuit
handshakes (CREATE2 and EXTEND2; the obsolete TAP handshake is not implemented),
authenticated SENDMEs for circuit flow control ([proposal 289](https://spec.torproject.org/proposals/289-authenticated-sendmes.html)),
microdescriptors without legacy TAP keys, and **version 3 onion services** (`.onion`
addresses of 56 characters), implemented from [rend-spec v3](https://spec.torproject.org/rend-spec/)
including client authorization (restricted discovery).  Version 2 onion services were
removed from the Tor network in 2021 and are no longer supported.

![Orchid](https://subgraph.com/img/orchidlogo1.png)

## How can Orchid be used?

Orchid can be used as a standalone client where [the canonical Tor](https://www.torproject.org/) would otherwise be used.  Orchid acts as a SOCKS5 proxy.

Orchid can also be used as a library by any application running on the JVM. This is what Orchid was really designed for and this is the recommended way to use it. Orchid can be used as a library in any Java application, or any application written in a language that compiles bytecode that will run on the Java virtual machine, e.g. JRuby, Clojure, Scala...

## How to build

Orchid uses [Gradle](https://gradle.org/) (8.x) as its build system.

```
gradle build
```

will compile, run the unit tests and produce a JAR in the `build/libs` directory.

```
gradle fatJar
```

will produce a fat JAR (`Orchid-<version>-all.jar`), which contains both classes and dependencies needed to run Orchid as a standalone client.

If you cannot reach Maven Central, drop the dependency jars into `lib/` (see `lib/README`).

The version comes from the git tag (`git describe`): a build of the commit tagged
`v2.0.0` is version `2.0.0`, and a later commit builds as, for example,
`2.0.0-3-g1234abcd`.  There is no version number to edit in the source; to make
a release, tag the commit (`git tag -a v2.0.1`) and build it.

You may find prebuilt JARs in [Releases](https://github.com/mhatta/Orchid/releases).

The old Ant build system (`build.xml`) is unmaintained.

## How to run

To start the Orchid SOCKS5 proxy, perform the following:

```
java -jar Orchid-<version>-all.jar
```

To test Orchid, you can tell your web browser to use Orchid as a SOCKS5 proxy (the default listening port is `9150`) - however it is important to note that Orchid + your browser is **NOT** a secure replacement for [the Tor Browser Bundle](https://www.torproject.org/projects/torbrowser.htm), which has many other enhancements beyond Tor.

For example, with Mozilla Firefox, by default, DNS lookups are not sent over a configured SOCKS5 proxy. You can change this potentially de-anonymizing default configuration by going to the URL `about:config` and setting the property `network.proxy.socks_remote_dns` to `true` (this is already done in the Tor Browser).

## Using the dashboard

Orchid also includes a "dashboard" feature to observe information about the internal state of Tor. To start the dashboard, set the following property when the JAR is run like:

```
java -Dcom.subgraph.orchid.dashboard.port=10000 -jar Orchid-<version>-all.jar
```

To access the dashboard, just connect to the port (for this example `10000`) with netcat.

## Connecting to onion services

Any v3 onion address can be used as a SOCKS5 destination.  For services that use
client authorization (restricted discovery), register the client's x25519 private
key with the configuration, using the key encoding of Tor's `ClientOnionAuthDir` files:

```java
TorConfig config = client.getConfig();
config.addOnionClientAuth("xxxx...xxxx.onion", "<52 character base32 private key>");
```

## How to use as a library

The Orchid Tor client exposes a SocketFactory that can be used within a JVM application. More detailed documentation and code examples are coming very soon.  [This Stack Overflow discussion](https://stackoverflow.com/questions/29171643/java-tor-lib-how-to-setup-orchid-tor-lib-with-java) might be helpful for now.

## Authors

Orchid was originally developed by [Bruce Leidl](https://github.com/brl) of [Subgraph](https://subgraph.com/).  The original web page can be found [here](https://subgraph.com/orchid/).  This README borrows heavily from there.

This fork is currently maintained by [Masayuki Hatta](http://about.me/mhatta) ([@mhatta](https://twitter.com/mhatta)).

## Acknowledgements

The current Orchid has been incorporated with various improvements from the following projects/people:

* [bitcoinj](https://github.com/bitcoinj)
* [geo-gs](https://github.com/geo-gs)
* [peergos](https://github.com/peergos)

## License

This project is licensed under the 3-clause BSD License - see the [LICENSE](LICENSE) for details.

## Demo

A typical Orchid run will output something like this:


```
2018-04-06 04:06:10,458 INFO - TorClient - Starting Orchid (version: 1.0.0)
2018-04-06 04:06:10,461 INFO - DirectoryImpl - Loading cached network information from disk
2018-04-06 04:06:10,461 INFO - DirectoryImpl - Loading certificates
2018-04-06 04:06:15,582 INFO - DirectoryImpl - Loading consensus
2018-04-06 04:06:15,615 INFO - DirectoryImpl - Loading microdescriptor cache
2018-04-06 04:06:15,616 INFO - DirectoryImpl - loading state file
2018-04-06 04:06:15,617 INFO - DirectoryDownloadTask - Downloading consensus because we have no consensus document
2018-04-06 04:06:15,713 INFO - TorClient - >>> [ 5% ]: Connecting to directory server
2018-04-06 04:06:15,947 INFO - TorClient - >>> [ 10% ]: Finishing handshake with directory server
2018-04-06 04:10:12,024 INFO - TorClient - >>> [ 15% ]: Establishing an encrypted directory connection
2018-04-06 04:10:12,718 INFO - TorClient - >>> [ 20% ]: Asking for networkstatus consensus
2018-04-06 04:10:13,014 INFO - TorClient - >>> [ 25% ]: Loading networkstatus consensus
2018-04-06 04:10:17,877 INFO - ConsensusDocumentImpl - Certificates need to be retrieved to verify consensus
2018-04-06 04:20:25,616 INFO - TorClient - >>> [ 35% ]: Asking for authority key certs
2018-04-06 04:20:25,900 INFO - TorClient - >>> [ 40% ]: Loading authority key certs
2018-04-06 04:20:31,612 INFO - TorClient - >>> [ 45% ]: Asking for relay descriptors
2018-04-06 04:20:31,662 INFO - TorClient - >>> [ 50% ]: Loading relay descriptors
2018-04-06 04:20:35,680 INFO - TorClient - >>> [ 80% ]: Connecting to the Tor network
2018-04-06 04:20:35,804 INFO - TorClient - >>> [ 85% ]: Finished Handshake with first hop
2018-04-06 04:28:14,594 INFO - TorClient - >>> [ 90% ]: Establishing a Tor circuit
2018-04-06 04:28:15,362 INFO - TorClient - >>> [ 100% ]: Done
2018-04-06 04:28:15,362 INFO - TorClient - Tor is ready to go!
```

There will be a lot of `INFO - CircuitCreationTask - Cannot build circuits because we don't have enough directory information` warnings and pauses during the session.  It is usually OK, be patient.  The first time run will take much longer time than the sessions hereafter.

## Directory information

Like Tor, Orchid downloads the consensus and the relay descriptors from
directory caches (relays with the `V2Dir` flag) over the ORPort.  Until it has
a consensus it uses the fallback directories that Tor ships, and only rarely a
directory authority.  The fallback list is compiled into
`FallbackDirectoryList.java`; refresh it from a current Tor release from time
to time:

```
tools/gen-fallback-dirs.py /path/to/tor/src/app/config/fallback_dirs.inc \
    > src/main/java/com/subgraph/orchid/directory/FallbackDirectoryList.java
```
