package com.subgraph.orchid.circuits.guards;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.subgraph.orchid.BridgeRouter;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigBridgeLine;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.directory.downloader.DirectoryRequestFailedException;
import com.subgraph.orchid.logging.Logger;

public class Bridges {
    private static final Logger logger = Logger.getInstance(Bridges.class);
	
    private class DescriptorDownloader implements Runnable {

        private final BridgeRouterImpl target;

        DescriptorDownloader(BridgeRouterImpl target) {
            this.target = target;
        }

        public void run() {
            try {
                downloadDescriptor();
            } finally {
                decrementOutstandingTasks();
            }
        }

        private void downloadDescriptor() {
            logger.debug("Downloading descriptor for bridge: "+ target);
            try {
                final RouterDescriptor descriptor = directoryDownloader.downloadBridgeDescriptor(target);
                if(descriptor != null && !isDescriptorOf(target, descriptor)) {
                    logger.warn("Descriptor received from a bridge is for another router; the bridge is not used");
                    return;
                }
                if(descriptor != null) {
                    logger.debug("Descriptor received for bridge "+ target +". Adding to list of usable bridges");
                    target.setDescriptor(descriptor);
                    synchronized(lock) {
                        bridgeRouters.add(target);
                        lock.notifyAll();
                    }
                }
            } catch (DirectoryRequestFailedException e) {
                logger.warn("Failed to download descriptor for bridge: "+ e.getMessage());
            }
        }

        private void decrementOutstandingTasks() {
            if(outstandingDownloadTasks.decrementAndGet() == 0) {
                logger.debug("Initial descriptor fetch complete");
                synchronized(lock) {
                    bridgesInitialized = true;
                    lock.notifyAll();
                }
            }
        }
    }

    private final TorConfig config;
    private final DirectoryDownloader directoryDownloader;

    private final Set<BridgeRouterImpl> bridgeRouters;
    private final TorRandom random;
    private final Object lock;

    /** Initialization started */
    private boolean bridgesInitializing;
    /** Initialization completed */
    private boolean bridgesInitialized;

    private AtomicInteger outstandingDownloadTasks;

    Bridges(TorConfig config, DirectoryDownloader directoryDownloader) {
        this.config = config;
        this.directoryDownloader = directoryDownloader;
        this.bridgeRouters = new HashSet<BridgeRouterImpl>();
        this.random = new TorRandom();
        this.lock = new Object();
        this.outstandingDownloadTasks = new AtomicInteger();
    }

    BridgeRouter chooseRandomBridge(Set<Router> excluded) throws InterruptedException {

        synchronized(lock) {
            if(!bridgesInitialized && !bridgesInitializing) {
                    initializeBridges();
            }
            while(!bridgesInitialized && !hasCandidates(excluded)) {
                lock.wait();
            }
            final List<BridgeRouter> candidates = getCandidates(excluded);
            if(candidates.isEmpty()) {
                logger.warn("Bridges enabled but no usable bridges configured");
                return null;
            }
            return candidates.get(random.nextInt(candidates.size()));
        }
    }

    private boolean hasCandidates(Set<Router> excluded) {
        return !(getCandidates(excluded).isEmpty());
    }
	
    private List<BridgeRouter> getCandidates(Set<Router> excluded) {
        if(bridgeRouters.isEmpty()) {
            return Collections.emptyList();
        }
        final List<BridgeRouter> candidates = new ArrayList<BridgeRouter>(bridgeRouters.size());
        for(BridgeRouter br: bridgeRouters) {
            if(!excluded.contains(br)) {
                candidates.add(br);
            }
        }
        return candidates;
    }

    private void initializeBridges() {
        logger.debug("Initializing bridges...");
        synchronized(lock) {
            if(bridgesInitializing || bridgesInitialized) {
                return;
            }
            if(directoryDownloader == null) {
                throw new IllegalStateException("Cannot download bridge descriptors because DirectoryDownload instance not initialized");
            }
            bridgesInitializing = true;
            startAllDownloadTasks();
        }
    }
	
    private List<Runnable> createDownloadTasks() {
        final List<Runnable> tasks = new ArrayList<Runnable>();
        int withoutFingerprint = 0;
        for(TorConfigBridgeLine line: config.getBridges()) {
            if(line.getFingerprint() == null) {
                withoutFingerprint++;
            }
            tasks.add(new DescriptorDownloader(createBridgeFromLine(line)));
        }
        if(withoutFingerprint > 0) {
            /* No address in the message: bridge addresses are meant to stay unpublished. */
            logger.warn(withoutFingerprint +" of "+ tasks.size() +" bridge lines have no fingerprint. Orchid then"
                    + " trusts whatever relay answers at that address on the first connection, which anyone on"
                    + " the path to it can impersonate. Add the fingerprint from the bridge line you were given.");
        }
        return tasks;
    }
	
    private void startAllDownloadTasks() {
        final List<Runnable> tasks = createDownloadTasks();
        outstandingDownloadTasks.set(tasks.size());
        for(Runnable r: tasks) {
            final Thread thread = new Thread(r);
            thread.start();
        }
    }
	
    /*
     * The descriptor must be the bridge's own: its identity key must be the
     * one the bridge proved in the link handshake, which is the fingerprint
     * of the bridge line when it has one.  The descriptor's signature has
     * been checked against that same key, so this binds the descriptor's
     * onion keys and Ed25519 identity to the bridge.  Without the check a
     * bridge could hand out the descriptor of another router, and circuits
     * would be extended with that router's keys.
     */
    static boolean isDescriptorOf(BridgeRouter bridge, RouterDescriptor descriptor) {
        final HexDigest identity = bridge.getIdentityHash();
        final TorPublicKey key = descriptor.getIdentityKey();
        if(identity == null || key == null) {
            return false;
        }
        return identity.equals(key.getFingerprint());
    }

    private BridgeRouterImpl createBridgeFromLine(TorConfigBridgeLine line) {
        final BridgeRouterImpl bridge = new BridgeRouterImpl(line.getAddress(), line.getPort());
        if(line.getFingerprint() != null) {
            bridge.setIdentity(line.getFingerprint());
        }
        return bridge;
    }
}
