package com.subgraph.orchid.circuits.hs;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.CircuitManagerImpl;
import com.subgraph.orchid.logging.Logger;

/**
 * Entry point for connecting to version 3 onion services ("hidden services").
 * Version 2 onion services were removed from the Tor network in 2021 and are
 * no longer supported.
 */
public class HiddenServiceManager {
    private static final Logger logger = Logger.getInstance(HiddenServiceManager.class);
    private final static int RENDEZVOUS_RETRY_COUNT = 5;
    private final static int HS_STREAM_TIMEOUT = 20000;
    /*
     * How long onion service code waits for a clean internal circuit before
     * giving up (it used to wait for ever).  Twice the default circuit build
     * timeout.
     */
    final static long INTERNAL_CIRCUIT_WAIT_MS = 2 * 60 * 1000;

    private final Map<String, HiddenService> hiddenServices;
    private final TorConfig config;
    private final Directory directory;
    private final HSV3Directories hsDirectories;
    private final CircuitManagerImpl circuitManager;

    public HiddenServiceManager(TorConfig config, Directory directory, CircuitManagerImpl circuitManager) {
        this.config = config;
        this.directory = directory;
        this.hiddenServices = new HashMap<String, HiddenService>();
        this.hsDirectories = new HSV3Directories(directory);
        this.circuitManager = circuitManager;
    }

    public Stream getStreamTo(String onion, int port) throws OpenFailedException, InterruptedException, TimeoutException {
        return getStreamTo(onion, port, null);
    }

    /**
     * As {@link #getStreamTo(String, int)}, on a rendezvous circuit used only
     * by streams with the same isolation key: streams to one service with
     * different keys get circuits of their own.
     */
    public Stream getStreamTo(String onion, int port, String isolationKey) throws OpenFailedException, InterruptedException, TimeoutException {
        final HiddenService hs = getHiddenServiceForOnion(onion);
        /*
         * A cached circuit can die between the check in getCircuitTo() and
         * the stream request.  When the stream fails because the circuit is
         * gone, forget the circuit and try once more on a new one; any other
         * failure (the service refused the port, say) is reported as is.
         */
        for(int attempt = 0; ; attempt++) {
            final HiddenServiceCircuit circuit = getCircuitTo(hs, isolationKey);
            try {
                return circuit.openStream(port, HS_STREAM_TIMEOUT);
            } catch (StreamConnectFailedException e) {
                if(!circuit.isConnected() && attempt == 0) {
                    discard(hs, circuit);
                    continue;
                }
                throw new OpenFailedException("Failed to open stream to hidden service "+ hs.getOnionAddressForLogging() + " reason "+ e.getReason());
            } catch (TimeoutException e) {
                // A circuit on which a stream got no answer is not reused.
                discard(hs, circuit);
                if(!circuit.isConnected() && attempt == 0) {
                    continue;
                }
                throw e;
            }
        }
    }

    private static void discard(HiddenService hs, HiddenServiceCircuit circuit) {
        hs.discardCircuit(circuit);
        circuit.markForClose();
    }

    /*
     * Locks only this service: opening a rendezvous circuit takes up to
     * several minutes (descriptor download and up to RENDEZVOUS_RETRY_COUNT
     * attempts), and with one lock for the whole manager a single onion that
     * does not answer held up the streams to every other onion service.
     */
    private HiddenServiceCircuit getCircuitTo(HiddenService hs, String isolationKey) throws OpenFailedException, InterruptedException {
        synchronized(hs.getConnectLock()) {
            final HiddenServiceCircuit existing = hs.getCircuit(isolationKey);
            if(existing != null) {
                return existing;
            }
            final HiddenServiceCircuit c = openCircuitTo(hs);
            if(c == null) {
                throw new OpenFailedException("Failed to open circuit to "+ hs.getOnionAddressForLogging());
            }
            hs.setCircuit(isolationKey, c);
            return c;
        }
    }

    private HiddenServiceCircuit openCircuitTo(HiddenService hs) throws OpenFailedException {
        final HSV3Descriptor descriptor = getDescriptorFor(hs);
        if(descriptor.isIntroAuthRequired()) {
            throw new OpenFailedException("Hidden service "+ hs.getOnionAddressForLogging() + " requires introduction-point authentication, which is not supported");
        }
        if(descriptor.getIntroductionPoints().isEmpty()) {
            throw new OpenFailedException("Descriptor for "+ hs.getOnionAddressForLogging() + " lists no usable introduction points");
        }

        for(int i = 0; i < RENDEZVOUS_RETRY_COUNT; i++) {
            final HiddenServiceCircuit c = openRendezvousCircuit(hs, descriptor);
            if(c != null) {
                return c;
            }
        }
        throw new OpenFailedException("Failed to open circuit to "+ hs.getOnionAddressForLogging());
    }

    HSV3Descriptor getDescriptorFor(HiddenService hs) throws OpenFailedException {
        final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
        if(consensus == null) {
            throw new OpenFailedException("No consensus document available; cannot locate hidden service directories");
        }
        /* The time period (and hence the blinded key) follows the consensus valid-after time. */
        final HSV3TimePeriod tp = HSV3TimePeriod.fromConsensus(consensus);
        hs.updateTimePeriod(tp);

        if(hs.hasCurrentDescriptor()) {
            return hs.getDescriptor();
        }
        final HSV3Descriptor descriptor = downloadDescriptorFor(hs);
        if(descriptor == null) {
            final String msg = "Failed to download HS descriptor for "+ hs.getOnionAddressForLogging();
            logger.info(msg);
            throw new OpenFailedException(msg);
        }
        hs.setDescriptor(descriptor);
        return descriptor;
    }

    private HSV3Descriptor downloadDescriptorFor(HiddenService hs) {
        logger.debug("Downloading HS descriptor for "+ hs.getOnionAddressForLogging() + " in "+ hs.getTimePeriod());
        final List<Router> dirs = hsDirectories.getResponsibleDirectories(hs.getBlindedPublicKey(), hs.getTimePeriod());
        if(dirs.isEmpty()) {
            logger.info("No responsible HSDirs found for "+ hs.getOnionAddressForLogging());
            return null;
        }
        final HSV3DescriptorDownloader downloader = new HSV3DescriptorDownloader(hs, circuitManager, dirs);
        return downloader.downloadDescriptor();
    }

    HiddenService getHiddenServiceForOnion(String onion) throws OpenFailedException {
        final HSV3Address address = parseAddress(onion);
        synchronized(hiddenServices) {
            HiddenService hs = hiddenServices.get(address.getAddress());
            if(hs == null) {
                hs = new HiddenService(config, address);
                hiddenServices.put(address.getAddress(), hs);
            }
            return hs;
        }
    }

    private HSV3Address parseAddress(String onion) throws OpenFailedException {
        final String target = config.getSafeLogging() ? "[scrubbed]" : onion;
        try {
            return HSV3Address.parse(onion);
        } catch (TorException e) {
            if(!HSV3Address.isV3AddressLength(onion)) {
                throw new OpenFailedException("Unsupported onion address "+ target + ": only version 3 (56 character) onion addresses are supported; v2 services no longer exist on the Tor network");
            }
            throw new OpenFailedException("Failed to decode onion address "+ target + " : "+ e.getMessage());
        }
    }

    private HiddenServiceCircuit openRendezvousCircuit(HiddenService hs, HSV3Descriptor descriptor) {
        final RendezvousCircuitBuilder builder = new RendezvousCircuitBuilder(directory, circuitManager, hs, descriptor);
        try {
            return builder.call();
        } catch (Exception e) {
            logger.debug("Rendezvous attempt failed for "+ hs.getOnionAddressForLogging() + ": "+ e);
            return null;
        }
    }
}
