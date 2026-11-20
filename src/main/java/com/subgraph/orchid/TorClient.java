package com.subgraph.orchid;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.crypto.Cipher;
import javax.net.SocketFactory;

import com.subgraph.orchid.circuits.TorInitializationTracker;
import com.subgraph.orchid.circuits.path.TorConfigNodeFilter;
import com.subgraph.orchid.dashboard.Dashboard;
import com.subgraph.orchid.directory.DataDirectory;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.logging.SafeLogging;
import com.subgraph.orchid.misc.TrafficCounter;
import com.subgraph.orchid.sockets.OrchidSocketFactory;

/**
 * This class is the main entry-point for running a Tor proxy
 * or client.
 */
public class TorClient {
    private static final Logger logger = Logger.getInstance(TorClient.class);

    private final TorConfig config;
    private final Directory directory;
    private final TorInitializationTracker initializationTracker;
    private final ConnectionCache connectionCache;
    private final CircuitManager circuitManager;
    private final SocksPortListener socksListener;
    private final DirectoryDownloaderImpl directoryDownloader;
    private final Dashboard dashboard;
    private final TrafficCounter trafficCounter = new TrafficCounter();

    private final boolean usesDataDirectory;
    private boolean isStarted = false;
    private boolean isStopped = false;

    private final CountDownLatch readyLatch;

    public TorClient() {
            this(null);
    }

    public TorClient(DirectoryStore customDirectoryStore) {
            // A custom DirectoryStore keeps the state itself.
            usesDataDirectory = (customDirectoryStore == null);
            config = Tor.createConfig();
            SafeLogging.setEnabled(config.getSafeLogging());
            directory = Tor.createDirectory(config, customDirectoryStore);
            initializationTracker = Tor.createInitalizationTracker();
            initializationTracker.addListener(createReadyFlagInitializationListener());
            connectionCache = Tor.createConnectionCache(config, initializationTracker, trafficCounter);
            directoryDownloader = Tor.createDirectoryDownloader(config, initializationTracker);
            circuitManager = Tor.createCircuitManager(config, directoryDownloader, directory, connectionCache, initializationTracker, trafficCounter);
            socksListener = Tor.createSocksPortListener(config, circuitManager);
            readyLatch = new CountDownLatch(1);
            dashboard = new Dashboard();
            dashboard.addRenderables(circuitManager, directoryDownloader, socksListener);
    }

    public TorConfig getConfig() {
            return config;
    }

    public SocketFactory getSocketFactory() {
            return new OrchidSocketFactory(this);
    }

    /**
     * Start running the Tor client service.
     */
    public synchronized void start() {
            if(isStarted) {
                    return;
            }
            if(isStopped) {
                    throw new IllegalStateException("Cannot restart a TorClient instance.  Create a new instance instead.");
            }
            logger.info("Starting Orchid (version: "+ Tor.getFullVersion() +")");
            verifyUnlimitedStrengthPolicyInstalled();
            TorConfigNodeFilter.checkCountryCodes(config);
            if(usesDataDirectory) {
                    DataDirectory.prepare(config.getDataDirectory());
            }
            directoryDownloader.start(directory);
            circuitManager.startBuildingCircuits();
            if(dashboard.isEnabledByProperty()) {
                    dashboard.startListening();
            }
            isStarted = true;
    }

    public synchronized void stop() {
        if(!isStarted || isStopped) {
            return;
        }
        try {
            socksListener.stop();
            if(dashboard.isListening()) {
                dashboard.stopListening();
            }
            directoryDownloader.stop();
            circuitManager.stopBuildingCircuits(true);
            directory.close();
            connectionCache.close();
        } catch (Exception e) {
            logger.warn("Unexpected exception while shutting down TorClient instance.", e);
        } finally {
            isStopped = true;
        }
    }

    /**
     * Tell Orchid that the network changed, for example from Wi-Fi to
     * mobile data, or back online after a time without connectivity.  On
     * Android, call it from a <code>ConnectivityManager.NetworkCallback</code>
     * (<code>onAvailable()</code>, or <code>onLost()</code> of the network in
     * use).
     *
     * All connections to relays are closed, since connections made over
     * the old network would only fail when their TCP connections time out,
     * and the circuits on them are destroyed.  Entry guards that were found
     * unreachable are tried again.  New circuits are then built as usual;
     * streams open on the old circuits are closed.
     */
    public void notifyNetworkChanged() {
        ensureStarted();
        logger.info("Network changed: closing the connections to relays");
        circuitManager.networkChanged();
        directoryDownloader.networkChanged();
        connectionCache.closeAllConnections();
    }

    /**
     * Use new circuits for all streams opened from now on, so that new
     * activity cannot be linked through a shared exit relay with what was
     * done before: the "New identity" of a proxy app, or Tor's NEWNYM
     * signal.  Streams already open keep their circuits until they end.
     * Entry guards are kept, as in Tor.
     *
     * @since 2.8.0
     */
    public void newIdentity() {
        ensureStarted();
        circuitManager.newIdentity();
    }

    /**
     * How far Orchid is in starting up, from 0 to 100, as reported to
     * {@link TorInitializationListener#initializationProgress}.  100 means
     * that Orchid is ready to open streams.
     *
     * @since 2.8.0
     */
    public int getBootstrapPercent() {
        return initializationTracker.getBootstrapState();
    }

    /**
     * The message for the current bootstrap step ("Loading relay
     * descriptors"), as reported to
     * {@link TorInitializationListener#initializationProgress}.
     *
     * @since 2.8.0
     */
    public String getBootstrapMessage() {
        return initializationTracker.getBootstrapMessage();
    }

    /**
     * A snapshot of the circuits Orchid has open or is building, for showing
     * to users.  The list does not change afterwards; call again for a new
     * one.  It holds no stream isolation keys (see {@link CircuitInfo}).
     * Do not call it on the main thread of an Android app: the first call
     * may load the GeoIP database for the country codes.  The relays are
     * sensitive: see {@link RelayInfo}.
     *
     * @since 2.8.0
     */
    public List<CircuitInfo> getCircuits() {
        return circuitManager.getCircuitInfo();
    }

    /**
     * A snapshot of the entry guards Orchid has sampled (guard-spec),
     * primary guards first in the order they are used.  Empty before the
     * guard state is loaded, when entry guards are not used, and with
     * bridges.  The guards identify the client for months: show them to the
     * user, but see {@link RelayInfo} for what not to do with them.  Not on
     * the main thread of an Android app, as {@link #getCircuits()}.
     *
     * @since 2.8.0
     */
    public List<GuardInfo> getEntryGuards() {
        return circuitManager.getEntryGuardInfo();
    }

    /**
     * How many bytes this client has sent and received since it was
     * created: the cells exchanged with relays, and the data of the
     * applications' streams.  See {@link TrafficInfo} for what each counter
     * includes.  Cheap: it reads four counters and may be called from any
     * thread, the main thread of an Android app included, for example once
     * a second to show the bandwidth.
     *
     * @since 2.8.0
     */
    public TrafficInfo getTrafficInfo() {
        return trafficCounter.getTrafficInfo();
    }

    public Directory getDirectory() {
        return directory;
    }

    public ConnectionCache getConnectionCache() {
        return connectionCache;
    }

    public CircuitManager getCircuitManager() {
        return circuitManager;
    }

    public void waitUntilReady() throws InterruptedException {
        readyLatch.await();
    }

    public void waitUntilReady(long timeout) throws InterruptedException, TimeoutException {
        if(!readyLatch.await(timeout, TimeUnit.MILLISECONDS)) {
            throw new TimeoutException();
        }
    }

    public Stream openExitStreamTo(String hostname, int port) throws InterruptedException, TimeoutException, OpenFailedException {
        ensureStarted();
        return circuitManager.openExitStreamTo(hostname, port);
    }

    /**
     * Open a stream on circuits used only by streams with the same
     * isolation key.  See {@link CircuitManager#openExitStreamTo(String, int, String)}.
     */
    public Stream openExitStreamTo(String hostname, int port, String isolationKey) throws InterruptedException, TimeoutException, OpenFailedException {
        ensureStarted();
        return circuitManager.openExitStreamTo(hostname, port, isolationKey);
    }

    /**
     * A SocketFactory whose sockets use circuits of their own, shared only
     * with sockets of factories with the same isolation key.
     */
    public SocketFactory getSocketFactory(String isolationKey) {
        return new OrchidSocketFactory(this, true, isolationKey);
    }

    private synchronized void ensureStarted() {
        if(!isStarted) {
            throw new IllegalStateException("Must call start() first");
        }
    }

    public void enableSocksListener(int port) {
        socksListener.addListeningPort(port);
    }

    /**
     * Accept HTTP CONNECT requests on <code>port</code> (Tor's
     * HTTPTunnelPort), for applications and settings that can use only an
     * HTTP proxy, such as the Wi-Fi proxy setting of Android.  Only CONNECT
     * is served, which is what clients use for https:// URLs; plain HTTP
     * requests are refused.  The port is bound like the SOCKS port (see
     * {@link TorConfig#getSocksListenAddress()}), is protected by the same
     * password if one is set ({@link TorConfig#setSocksPassword(String)}),
     * and isolates streams by the user name and password of the
     * <code>Proxy-Authorization</code> header as the SOCKS port does by the
     * SOCKS credentials.
     *
     * @since 2.8.0
     */
    public void enableHttpTunnelListener(int port) {
        socksListener.addHttpTunnelPort(port);
    }

    public void enableSocksListener() {
        enableSocksListener(9150);
    }

    public void enableDashboard() {
        if(!dashboard.isListening()) {
            dashboard.startListening();
        }
    }

    public void enableDashboard(int port) {
        dashboard.setListeningPort(port);
        enableDashboard();
    }

    public void disableDashboard() {
        if(dashboard.isListening()) {
            dashboard.stopListening();
        }
    }

    public void addInitializationListener(TorInitializationListener listener) {
        initializationTracker.addListener(listener);
    }

    public void removeInitializationListener(TorInitializationListener listener) {
        initializationTracker.removeListener(listener);
    }

    private TorInitializationListener createReadyFlagInitializationListener() {
        return new TorInitializationListener() {
            public void initializationProgress(String message, int percent) {}
            public void initializationCompleted() {
                readyLatch.countDown();
            }
        };
    }

    public static void main(String[] args) {
        final TorClient client = new TorClient();
        client.addInitializationListener(createInitalizationListner());
        client.start();
        client.enableSocksListener();
    }

    private static TorInitializationListener createInitalizationListner() {
        return new TorInitializationListener() {
            public void initializationProgress(String message, int percent) {
                logger.info(">>> [ "+ percent + "% ]: "+ message);
            }

            public void initializationCompleted() {
                logger.info("Tor is ready to go!");
            }
        };
    }

    private void verifyUnlimitedStrengthPolicyInstalled() {
        try {
            if(Cipher.getMaxAllowedKeyLength("AES") < 256) {
                final String message = "Unlimited Strength Jurisdiction Policy Files are required but not installed.";
                logger.fatal(message);
                throw new TorException(message);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.fatal("No AES provider found");
            throw new TorException(e);
        }  catch (NoSuchMethodError e) {
            logger.info("Skipped check for Unlimited Strength Jurisdiction Policy Files");
        }
    }
}
