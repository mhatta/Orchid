package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitInfo;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.DirectoryCircuit;
import com.subgraph.orchid.ExitCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.RelayInfo;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.path.CircuitPathChooser;
import com.subgraph.orchid.circuits.path.PathSelectionFailedException;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.misc.TrafficCounter;

/**
 * This class represents an established circuit through the Tor network.
 */
public abstract class CircuitImpl implements Circuit, DashboardRenderable {
    private static final Logger logger = Logger.getInstance(CircuitImpl.class);

    static ExitCircuit createExitCircuit(CircuitManagerImpl circuitManager, Router exitRouter) {
        return new ExitCircuitImpl(circuitManager, exitRouter);
    }

    static ExitCircuit createExitCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
        return new ExitCircuitImpl(circuitManager, prechosenPath);
    }

    static DirectoryCircuit createDirectoryCircuit(CircuitManagerImpl circuitManager) {
        return new DirectoryCircuitImpl(circuitManager, null);
    }

    static DirectoryCircuit createDirectoryCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
        return new DirectoryCircuitImpl(circuitManager, prechosenPath);
    }

    static InternalCircuit createInternalCircuitTo(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
        return new InternalCircuitImpl(circuitManager, prechosenPath);
    }

    private final CircuitManagerImpl circuitManager;
    protected final List<Router> prechosenPath;

    private final List<CircuitNode> nodeList;
    private final CircuitStatus status;

    private CircuitIO io;

    /*
     * A circuit built in advance and never used is closed after a random
     * time between half of CircuitIdleTimeout and all of it (30 to 60
     * minutes by default), as Tor closes unused circuits
     * (CircuitsAvailableTimeout, formerly CircuitIdleTimeout).  Without it
     * they stayed open for ever, and so did the connection to the guard,
     * which pads a quiet connection every few seconds: a device's radio was
     * never allowed to rest.  If the port is still predicted, the circuit
     * creation task builds a fresh one.  Random, so that the circuits do
     * not all close at once.
     */
    final static long DEFAULT_CIRCUIT_IDLE_TIMEOUT = 60 * 60 * 1000;
    private final long unusedLifetime;

    static long chooseUnusedLifetime(long circuitIdleTimeout) {
        final long half = Math.max(1, circuitIdleTimeout / 2);
        return half + new TorRandom().nextLong(half);
    }

    /** Whether the circuit is open, has never carried a stream and has been so for longer than its unused lifetime. */
    boolean isUnusedTooLong() {
        return isConnected() && isClean() && !isMarkedForClose()
                && getActiveStreams().isEmpty()
                && status.getMillisecondsElapsedSinceCreated() > unusedLifetime;
    }

    long getUnusedLifetime() {
        return unusedLifetime;
    }

    /** The traffic counter of the circuit manager, or null in tests without one. */
    TrafficCounter getTrafficCounter() {
        return (circuitManager == null) ? null : circuitManager.getTrafficCounter();
    }

    /** The path chooser of the circuit manager, or null in tests without one. */
    CircuitPathChooser getPathChooser() {
        return (circuitManager == null) ? null : circuitManager.getPathChooser();
    }

    protected CircuitImpl(CircuitManagerImpl circuitManager) {
        this(circuitManager, null);
    }

    protected CircuitImpl(CircuitManagerImpl circuitManager, List<Router> prechosenPath) {
        /*
         * Read by the cell reading thread (to decrypt each cell) while the
         * building thread appends hops, so the list must be safe to read
         * while it changes.  It changes only a few times per circuit.
         */
        nodeList = new CopyOnWriteArrayList<CircuitNode>();
        this.circuitManager = circuitManager;
        this.prechosenPath = prechosenPath;
        this.unusedLifetime = chooseUnusedLifetime((circuitManager == null)
                ? DEFAULT_CIRCUIT_IDLE_TIMEOUT : circuitManager.getConfig().getCircuitIdleTimeout());
        status = new CircuitStatus();
    }

    List<Router> choosePath(CircuitPathChooser pathChooser) throws InterruptedException, PathSelectionFailedException {
        if(prechosenPath != null) {
            return new ArrayList<Router>(prechosenPath);
        } else {
            return choosePathForCircuit(pathChooser);
        }
    }

    protected abstract List<Router> choosePathForCircuit(CircuitPathChooser pathChooser) throws InterruptedException, PathSelectionFailedException;

    void bindToConnection(Connection connection) {
        if(io != null) {
            throw new IllegalStateException("Circuit already bound to a connection");
        }
        final int id = connection.bindCircuit(this);
        io = new CircuitIO(this, connection, id);
    }

    public void markForClose() {
        if(io != null) {
            io.markForClose();
        }
    }

    public boolean isMarkedForClose() {
        if(retireWhenBuilt) {
            return true;
        }
        if(io == null) {
            return false;
        } else {
            return io.isMarkedForClose();
        }
    }

    /*
     * Set by retire() on a circuit that is still being built: it is marked
     * for close as soon as the build completes, so that it never carries a
     * stream.  Closing it in the middle of the build would make the build
     * fail and count, wrongly, against the entry guard.
     */
    private volatile boolean retireWhenBuilt;
    private final Object retireLock = new Object();

    /**
     * Take no more streams on this circuit, and close it once the streams on
     * it have ended (Tor's NEWNYM).  A circuit still being built is closed
     * when the build completes.
     */
    void retire() {
        synchronized(retireLock) {
            if(!status.isConnected()) {
                retireWhenBuilt = true;
                return;
            }
        }
        markForClose();
    }

    CircuitStatus getStatus() {
        return status;
    }

    public boolean isConnected() {
        return status.isConnected();
    }

    public boolean isPending() {
        return status.isBuilding();
    }

    public boolean isClean() {
        return !status.isDirty();
    }

    public int getSecondsDirty() {
        return (int) (status.getMillisecondsDirty() / 1000);
    }

    void notifyCircuitBuildStart() {
        if(!status.isUnconnected()) {
            throw new IllegalStateException("Can only connect UNCONNECTED circuits");
        }
        status.updateCreatedTimestamp();
        status.setStateBuilding();
        circuitManager.addActiveCircuit(this);
    }

    void notifyCircuitBuildFailed() {
        status.setStateFailed();
        circuitManager.removeActiveCircuit(this);
    }

    void notifyCircuitBuildCompleted() {
        synchronized(retireLock) {
            status.setStateOpen();
            status.updateCreatedTimestamp();
        }
        if(retireWhenBuilt) {
            markForClose();
        }
    }

    public Connection getConnection() {
        if(!isConnected()){
            throw new TorException("Circuit is not connected.");
        }
        return io.getConnection();
    }

    public int getCircuitId() {
        if(io == null) {
            return 0;
        } else {
            return io.getCircuitId();
        }
    }

    public void sendRelayCell(RelayCell cell) {
        io.sendRelayCellTo(cell, cell.getCircuitNode());
    }

    public void sendRelayCellToFinalNode(RelayCell cell) {
        io.sendRelayCellTo(cell, getFinalCircuitNode());
    }

    public void appendNode(CircuitNode node) {
        nodeList.add(node);
    }

    List<CircuitNode> getNodeList() {
        return nodeList;
    }

    int getCircuitLength() {
        return nodeList.size();
    }

    public CircuitNode getFinalCircuitNode() {
        if(nodeList.isEmpty()){
            throw new TorException("getFinalCircuitNode() called on empty circuit");
        }
        return nodeList.get( getCircuitLength() - 1);
    }

    public RelayCell createRelayCell(int relayCommand, int streamId, CircuitNode targetNode) {
        return io.createRelayCell(relayCommand, streamId, targetNode);
    }

    public RelayCell receiveRelayCell() {
        return io.dequeueRelayResponseCell();
    }

    void sendCell(Cell cell) {
        io.sendCell(cell);
    }

    Cell receiveControlCellResponse() {
        return io.receiveControlCellResponse();
    }

    /**
     * Why the circuit was destroyed, or null if it has not been.
     */
    String getDestroyReason() {
        return (io == null) ? null : io.getDestroyReason();
    }

    /*
     * This is called by the cell reading thread in ConnectionImpl to deliver control cells 
     * associated with this circuit (CREATED or CREATED_FAST).
     */
    public void deliverControlCell(Cell cell) {
        io.deliverControlCell(cell);
    }

    /* This is called by the cell reading thread in ConnectionImpl to deliver RELAY cells. */
    public void deliverRelayCell(Cell cell) {
        io.deliverRelayCell(cell);
    }

    protected StreamImpl createNewStream(boolean autoclose) {
        return io.createNewStream(autoclose);
    }
    protected StreamImpl createNewStream() {
        return createNewStream(false);
    }

    void setStateDestroyed() {
        status.setStateDestroyed();
        circuitManager.removeActiveCircuit(this);
    }

    public void destroyCircuit() {
        // We might not have bound this circuit yet
        if (io != null) {
            io.destroyCircuit();
        }
        circuitManager.removeActiveCircuit(this);
    }


    public void removeStream(StreamImpl stream) {
        io.removeStream(stream);
    }

    protected Stream processStreamOpenException(Exception e) throws InterruptedException, TimeoutException, StreamConnectFailedException {
        if(e instanceof InterruptedException) {
            throw (InterruptedException) e;
        } else if(e instanceof TimeoutException) {
            throw(TimeoutException) e;
        } else if(e instanceof StreamConnectFailedException) {
            throw(StreamConnectFailedException) e;
        } else {
            throw new IllegalStateException();
        }
    }

    protected abstract String getCircuitTypeLabel();

    /** What the circuit is for, for {@link #getInfo()}. */
    protected abstract CircuitInfo.Purpose getInfoPurpose();

    /** True if the circuit serves only streams with one isolation key. */
    protected boolean isIsolatedForInfo() {
        return false;
    }

    /** A snapshot of the circuit for applications: see TorClient#getCircuits(). */
    CircuitInfo getInfo() {
        final List<RelayInfo> path = new ArrayList<RelayInfo>();
        for(CircuitNode node: nodeList) {
            final Router r = node.getRouter();
            if(r != null) {
                path.add(relayInfo(r));
            }
        }
        final List<Stream> streams = getActiveStreams();
        return new CircuitInfo(getInfoPurpose(), getInfoState(), path, streams == null ? 0 : streams.size(),
                isIsolatedForInfo(), getSecondsDirty());
    }

    static RelayInfo relayInfo(Router r) {
        final HexDigest id = r.getIdentityHash();
        return new RelayInfo(id == null ? null : id.toString().toUpperCase(Locale.ROOT), r.getNickname(), r.getCountryCode());
    }

    private CircuitInfo.State getInfoState() {
        switch(status.getState()) {
        case OPEN:
            return isMarkedForClose() ? CircuitInfo.State.CLOSING : CircuitInfo.State.OPEN;
        case FAILED:
            return CircuitInfo.State.FAILED;
        case DESTROYED:
            return CircuitInfo.State.CLOSED;
        default:
            return CircuitInfo.State.BUILDING;
        }
    }

    public String toString() {
        return "  Circuit ("+ getCircuitTypeLabel() + ") id="+ Integer.toHexString(getCircuitId()) +" state=" + status.getStateAsString() +" "+ pathToString();
    }


    protected String pathToString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("[");
        for(CircuitNode node: nodeList) {
            if(sb.length() > 1){
                sb.append(",");
            }
            sb.append(node.toString());
        }
        sb.append("]");
        return sb.toString();
    }

    public List<Stream> getActiveStreams() {
        if(io == null) {
            return Collections.emptyList();
        } else {
            return io.getActiveStreams();
        }
    }

    public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException {
        if(io != null) {
            writer.println(toString());
            renderer.renderComponent(writer, flags, io);
        }
    }	
}
