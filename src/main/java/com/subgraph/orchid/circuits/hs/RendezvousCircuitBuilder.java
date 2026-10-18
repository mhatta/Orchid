package com.subgraph.orchid.circuits.hs;

import java.util.concurrent.Callable;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.CircuitManagerImpl;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.logging.Logger;

/**
 * Opens a rendezvous circuit to a version 3 onion service:
 * <ol>
 *   <li>pick a rendezvous point and send ESTABLISH_RENDEZVOUS,</li>
 *   <li>build a circuit to one of the service's introduction points and send
 *       INTRODUCE1 carrying the rendezvous point and the hs-ntor client key,</li>
 *   <li>wait for RENDEZVOUS2 on the rendezvous circuit and complete the
 *       handshake.</li>
 * </ol>
 */
public class RendezvousCircuitBuilder implements Callable<HiddenServiceCircuit>{
    private static final Logger logger = Logger.getInstance(RendezvousCircuitBuilder.class);

    private final Directory directory;
    private final CircuitManagerImpl circuitManager;
    private final HiddenService hiddenService;
    private final HSV3Descriptor serviceDescriptor;

    public RendezvousCircuitBuilder(Directory directory, CircuitManagerImpl circuitManager, HiddenService hiddenService, HSV3Descriptor descriptor) {
        this.directory = directory;
        this.circuitManager = circuitManager;
        this.hiddenService = hiddenService;
        this.serviceDescriptor = descriptor;
    }

    @Override
    public HiddenServiceCircuit call() throws Exception {

        logger.debug("Opening rendezvous circuit for "+ logServiceName());

        final InternalCircuit rendezvous = circuitManager.getCleanInternalCircuit();
        logger.debug("Establishing rendezvous for "+ logServiceName());
        final HSV3RendezvousProcessor rp = new HSV3RendezvousProcessor(rendezvous);
        if(!rp.establishRendezvous()) {
            rendezvous.markForClose();
            return null;
        }
        final Router rendezvousRouter = rp.getRendezvousRouter();
        if(rendezvousRouter == null || rendezvousRouter.getNTorOnionKey() == null) {
            logger.info("Rendezvous point has no ntor onion key");
            rendezvous.markForClose();
            return null;
        }

        logger.debug("Opening introduction circuit for "+ logServiceName());
        final HSV3IntroductionProcessor introductionProcessor = openIntroduction();
        if(introductionProcessor == null) {
            logger.info("Failed to open connection to any introduction point of "+ logServiceName());
            rendezvous.markForClose();
            return null;
        }
        final HSV3IntroductionPoint ip = introductionProcessor.getIntroductionPoint();
        final HSNtorKeyAgreement kex = new HSNtorKeyAgreement(ip.getAuthKey(), ip.getEncKey(), hiddenService.getSubcredential());

        logger.debug("Sending INTRODUCE1 for "+ logServiceName());
        final boolean icResult = introductionProcessor.sendIntroduce(kex, rp.getCookie(), rendezvousRouter);
        introductionProcessor.markCircuitForClose();
        if(!icResult) {
            rendezvous.markForClose();
            return null;
        }
        logger.debug("Processing RENDEZVOUS2 for "+ logServiceName());
        final HiddenServiceCircuit hsc = rp.processRendezvous2(kex);
        if(hsc == null) {
            rendezvous.markForClose();
            return null;
        }
        logger.debug("Rendezvous circuit opened for "+ logServiceName());
        return hsc;
    }

    private String logServiceName() {
        return hiddenService.getOnionAddressForLogging();
    }

    private HSV3IntroductionProcessor openIntroduction() {
        for(HSV3IntroductionPoint ip: serviceDescriptor.getShuffledIntroductionPoints()) {
            final Circuit circuit = attemptOpenIntroductionCircuit(ip);
            if(circuit != null) {
                return new HSV3IntroductionProcessor(hiddenService, circuit, ip);
            }
        }
        return null;
    }

    private Circuit attemptOpenIntroductionCircuit(HSV3IntroductionPoint ip) {
        final Router r = lookupIntroductionRouter(ip);
        if(r == null) {
            logger.debug("Introduction point "+ ip + " not found in directory");
            return null;
        }
        try {
            final InternalCircuit circuit = circuitManager.getCleanInternalCircuit();
            return circuit.cannibalizeToIntroductionPoint(r);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (TorException e) {
            logger.debug("cannibalizeTo() failed : "+ e.getMessage());
            return null;
        }
    }

    /**
     * Find the relay named by the introduction point's link specifiers.  The
     * legacy (RSA) identity is the lookup key; when the descriptor also carries
     * an ed25519 identity it must match the relay's.
     */
    private Router lookupIntroductionRouter(HSV3IntroductionPoint ip) {
        final HexDigest legacyId = ip.getLegacyIdentity();
        if(legacyId == null) {
            return null;
        }
        final Router r = directory.getRouterByIdentity(legacyId);
        if(r == null) {
            return null;
        }
        final byte[] edId = ip.getEd25519Identity();
        final byte[] routerEdId = r.getEd25519Identity();
        if(edId != null && routerEdId != null && !java.util.Arrays.equals(edId, routerEdId)) {
            logger.info("Introduction point ed25519 identity does not match directory information for "+ r);
            return null;
        }
        return r;
    }
}
