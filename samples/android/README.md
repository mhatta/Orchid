# Orchid Android sample

A minimal app that embeds Orchid as a library: it starts a `TorClient`,
shows the bootstrap progress, and fetches <https://check.torproject.org/api/ip>
through Tor with OkHttp.  It shows what an app that embeds Orchid has to do:

* **Data directory** under `Context#getNoBackupFilesDir()`, set before
  `start()` ([OrchidHolder](app/src/main/java/org/mhatta/orchid/sample/OrchidHolder.java)).
* **No backups**: `allowBackup="false"` and `dataExtractionRules` in the
  [manifest](app/src/main/AndroidManifest.xml), so that the entry guards and
  keys never leave the device.
* **Off the main thread**: `start()` and the requests run on an executor; the
  `TorInitializationListener` reports the progress.
* **Logging** to logcat with `Logger.setHandler()` (tag `Orchid`).
* **Network changes** reported with `notifyNetworkChanged()` from a
  `ConnectivityManager.NetworkCallback`.
* **OkHttp without DNS leaks** ([MainActivity](app/src/main/java/org/mhatta/orchid/sample/MainActivity.java)):
  Orchid's `SocketFactory` with an isolation key, and a `Dns` that returns
  `OrchidSocketFactory.unresolvedAddress(host)` so that names are resolved by
  the exit relay.  The SOCKS port is not used at all.

## Building

The sample builds Orchid from this checkout (see `settings.gradle`; remove
the `includeBuild` block to use `org.mhatta:orchid` from Maven Central).
It needs the Android SDK (`ANDROID_HOME` or `local.properties`) and JDK 17
or later:

```sh
cd samples/android
../../gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
adb logcat -s Orchid
```

The sample has not been built or run in CI.
