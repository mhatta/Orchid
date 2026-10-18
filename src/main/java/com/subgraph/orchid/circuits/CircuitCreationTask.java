package com.subgraph.orchid.circuits;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitBuildHandler;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.ExitCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.CircuitManagerImpl.CircuitFilter;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.data.exitpolicy.ExitTarget;
import com.subgraph.orchid.logging.Logger;

public class CircuitCreationTask implements Runnable {
    private static final Logger logger = Logger.getInstance(CircuitCreationTask.class);
    private final static int MAX_CIRCUIT_DIRTINESS = 300; // seconds
    private final static int MAX_PENDING_CIRCUITS = 4;

    private final TorConfig config;
    private final Directory directory;
    private final ConnectionCache connectionCache;
    private final CircuitManagerImpl circuitManager;
    private final TorInitializationTracker initializationTracker;
    private final CircuitPathChooser pathChooser;
    private final Executor executor;
    private final CircuitBuildHandler buildHandler;
    private final CircuitBuildHandler internalBuildHandler;
    // To avoid obnoxiously printing a warning every second
    private int notEnoughDirectoryInformationWarningCounter = 0;

    private final CircuitPredictor predictor;

    private final AtomicLong lastNewCircuit;

    CircuitCreationTask(TorConfig config, Directory directory, ConnectionCache connectionCache, CircuitPathChooser pathChooser, CircuitManagerImpl circuitManager, TorInitializationTracker initializationTracker) {
        this.config = config;
        this.directory = directory;
        this.connectionCache = connectionCache;
        this.circuitManager = circuitManager;
        this.initializationTracker = initializationTracker;
        this.pathChooser = pathChooser;
        this.executor = Threading.newPool("CircuitCreationTask worker");
        this.buildHandler = createCircuitBuildHandler();
        this.internalBuildHandler = createInternalCircuitBuildHandler();
        this.predictor = new CircuitPredictor();
        this.lastNewCircuit = new AtomicLong();
    }

    CircuitPredictor getCircuitPredictor() {
        return predictor;
    }

    @Override
    public void run() {
        expireOldCircuits();
        assignPendingStreamsToActiveCircuits();
        checkExpiredPendingCircuits();
        checkCircuitsForCreation();		
    }

    void predictPort(int port) {
        predictor.addExitPortRequest(port);
    }

    private void assignPendingStreamsToActiveCircuits() {
        final List<StreamExitRequest> pendingExitStreams = circuitManager.getPendingExitStreams();
        if(pendingExitStreams.isEmpty()){
            return;
        }

        for(ExitCircuit c: circuitManager.getRandomlyOrderedListOfExitCircuits()) {
            final Iterator<StreamExitRequest> it = pendingExitStreams.iterator();
            while(it.hasNext()) {
                if(attemptHandleStreamRequest(c, it.next())){
                    it.remove();
                }
            }
        }
    }

    private boolean attemptHandleStreamRequest(ExitCircuit c, StreamExitRequest request) {
        if(c.canHandleExitTo(request)) {
            if(request.reserveRequest()) {
                launchExitStreamTask(c, request);
            }
            // else request is reserved meaning another circuit is already trying to handle it
            return true;
        }
        return false;
    }

    private void launchExitStreamTask(ExitCircuit circuit, StreamExitRequest exitRequest) {
        final OpenExitStreamTask task = new OpenExitStreamTask(circuit, exitRequest);
        executor.execute(task);
    }

    private void expireOldCircuits() {
        final Set<Circuit> circuits = circuitManager.getCircuitsByFilter(new CircuitFilter() {
            @Override
            public boolean filter(Circuit circuit) {
                    return !circuit.isMarkedForClose() && circuit.getSecondsDirty() > MAX_CIRCUIT_DIRTINESS;
            }
        });
        for(Circuit c: circuits) {
            logger.debug("Closing idle dirty circuit: "+ c);
            ((CircuitImpl)c).markForClose();
        }
    }
    private void checkExpiredPendingCircuits() {
            // TODO Auto-generated method stub
    }

    private void checkCircuitsForCreation() {

            if(!directory.haveMinimumRouterInfo()) {
                    if(notEnoughDirectoryInformationWarningCounter % 50 == 0)
                            logger.info("Cannot build circuits because we don't have enough directory information");
                    notEnoughDirectoryInformationWarningCounter++;
                    return;
            }


            if(lastNewCircuit.get() != 0) {
                    final long now = System.currentTimeMillis();
                    if((now - lastNewCircuit.get()) < config.getNewCircuitPeriod()) {
                            // return;
                    }
            }

            buildCircuitIfNeeded();
            maybeBuildInternalCircuit();
    }

    private void buildCircuitIfNeeded() {
        if (connectionCache.isClosed()) {
            logger.warn("Not building circuits, because connection cache is closed");
            return;
        }

        final List<StreamExitRequest> pendingExitStreams = circuitManager.getPendingExitStreams();
        final List<PredictedPortTarget> predictedPorts = predictor.getPredictedPortTargets();
        final List<ExitTarget> exitTargets = new ArrayList<ExitTarget>();
        for(StreamExitRequest streamRequest: pendingExitStreams) {
            if(!streamRequest.isReserved() && countCircuitsSupportingTarget(streamRequest, false) == 0) {
                exitTargets.add(streamRequest);
            }
        }
        for(PredictedPortTarget ppt: predictedPorts) {
            if(countCircuitsSupportingTarget(ppt, true) < 2) {
                exitTargets.add(ppt);
            }
        }
        buildCircuitToHandleExitTargets(exitTargets);
    }

    private void maybeBuildInternalCircuit() {
        final int needed = circuitManager.getNeededCleanCircuitCount(predictor.isInternalPredicted());

        if(needed > 0) {
            launchBuildTaskForInternalCircuit();
        }
    }

    private void launchBuildTaskForInternalCircuit() {
        logger.debug("Launching new internal circuit");
        final InternalCircuitImpl circuit = new InternalCircuitImpl(circuitManager);
        final CircuitCreationRequest request = new CircuitCreationRequest(pathChooser, circuit, internalBuildHandler, false);
        final CircuitBuildTask task = new CircuitBuildTask(request, connectionCache, circuitManager.isNtorEnabled());
        executor.execute(task);
        circuitManager.incrementPendingInternalCircuitCount();
    }

    private int countCircuitsSupportingTarget(final ExitTarget target, final boolean needClean) {
        final CircuitFilter filter = new CircuitFilter() {
            public boolean filter(Circuit circuit) {
                if(!(circuit instanceof ExitCircuit)) {
                    return false;
                }
                final ExitCircuit ec = (ExitCircuit) circuit;
                final boolean pendingOrConnected = circuit.isPending() || circuit.isConnected();
                final boolean isCleanIfNeeded = !(needClean && !circuit.isClean());
                return pendingOrConnected && isCleanIfNeeded && ec.canHandleExitTo(target);
            }
        };
        return circuitManager.getCircuitsByFilter(filter).size();
    }

    private void buildCircuitToHandleExitTargets(List<ExitTarget> exitTargets) {
        if(exitTargets.isEmpty()){
            return;
        }
        if(!directory.haveMinimumRouterInfo()){
            return;
        }
        if(circuitManager.getPendingCircuitCount() >= MAX_PENDING_CIRCUITS){
            return;
        }

        logger.debug("Building new circuit to handle "+ exitTargets.size() +" pending streams and predicted ports");
        launchBuildTaskForTargets(exitTargets);
    }

    private void launchBuildTaskForTargets(List<ExitTarget> exitTargets) {
        final Router exitRouter = pathChooser.chooseExitNodeForTargets(exitTargets);
        if(exitRouter == null) {
            logger.warn("Failed to select suitable exit node for targets");
            return;
        }

        final Circuit circuit = circuitManager.createNewExitCircuit(exitRouter);
        final CircuitCreationRequest request = new CircuitCreationRequest(pathChooser, circuit, buildHandler, false);
        final CircuitBuildTask task = new  CircuitBuildTask(request, connectionCache, circuitManager.isNtorEnabled(), initializationTracker);
        executor.execute(task);
    }

    private CircuitBuildHandler createCircuitBuildHandler() {
        return new CircuitBuildHandler() {
            @Override
            public void circuitBuildCompleted(Circuit circuit) {
                logger.debug("Circuit completed to: "+ circuit);
                circuitOpenedHandler(circuit);
                lastNewCircuit.set(System.currentTimeMillis());
            }

            @Override
            public void circuitBuildFailed(String reason) {
                logger.info("Circuit build failed: "+ reason);
                buildCircuitIfNeeded();
            }

            @Override
            public void connectionCompleted(Connection connection) {
                logger.debug("Circuit connection completed to "+ connection);
            }

            @Override
            public void connectionFailed(String reason) {
                logger.info("Circuit connection failed: "+ reason);
                buildCircuitIfNeeded();
            }

            @Override
            public void nodeAdded(CircuitNode node) {
                logger.debug("Node added to circuit: "+ node);
            }	
        };
    }

    private void circuitOpenedHandler(Circuit circuit) {
        if(!(circuit instanceof ExitCircuit)) {
            return;
        }
        final ExitCircuit ec = (ExitCircuit) circuit;
        final List<StreamExitRequest> pendingExitStreams = circuitManager.getPendingExitStreams();
        for(StreamExitRequest req: pendingExitStreams) {
            if(ec.canHandleExitTo(req) && req.reserveRequest()) {
                launchExitStreamTask(ec, req);
            }
        }
    }

    private CircuitBuildHandler createInternalCircuitBuildHandler() {
        return new CircuitBuildHandler() {
            @Override
            public void nodeAdded(CircuitNode node) {
                logger.debug("Node added to internal circuit: "+ node);
            }

            @Override
            public void connectionFailed(String reason) {
                logger.info("Circuit connection failed: "+ reason);
                circuitManager.decrementPendingInternalCircuitCount();
            }

            @Override
            public void connectionCompleted(Connection connection) {
                logger.debug("Circuit connection completed to "+ connection);
            }

            @Override
            public void circuitBuildFailed(String reason) {
                logger.info("Circuit build failed: "+ reason);
                circuitManager.decrementPendingInternalCircuitCount();
            }

            @Override
            public void circuitBuildCompleted(Circuit circuit) {
                logger.debug("Internal circuit build completed: "+ circuit);
                lastNewCircuit.set(System.currentTimeMillis());
                circuitManager.addCleanInternalCircuit((InternalCircuit) circuit);
            }
        };
    }
}
