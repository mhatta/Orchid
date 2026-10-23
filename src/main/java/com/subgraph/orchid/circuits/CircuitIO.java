package com.subgraph.orchid.circuits;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionIOException;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;
import com.subgraph.orchid.logging.Logger;

public class CircuitIO implements DashboardRenderable {
    private static final Logger logger = Logger.getInstance(CircuitIO.class);
    final static long CIRCUIT_BUILD_TIMEOUT_MS = 30 * 1000;
    private final static long CIRCUIT_RELAY_RESPONSE_TIMEOUT = 20 * 1000;

    /*
     * Added to the response queues when the circuit is destroyed, so that a
     * thread waiting for CREATED_FAST, EXTENDED2 or another reply returns at
     * once instead of waiting until the build or response timeout expires.
     */
    private final static Cell DESTROYED_CONTROL_CELL = CellImpl.createCell(0, 0);
    private final static RelayCell DESTROYED_RELAY_CELL = new RelayCellImpl(null, 0, 0, 0);

    private volatile String destroyReason;

    private final CircuitImpl circuit;
    private final Connection connection;
    private final int circuitId;

    private final BlockingQueue<RelayCell> relayCellResponseQueue;
    private final BlockingQueue<Cell> controlCellResponseQueue;
    private final Map<Integer, StreamImpl> streamMap;
    private final ReentrantLock streamLock = Threading.lock("stream");
    private final ReentrantLock relaySendLock = Threading.lock("relaySend");

    private boolean isMarkedForClose;
    private boolean isClosed;

    CircuitIO(CircuitImpl circuit, Connection connection, int circuitId) {
        this.circuit = circuit;
        this.connection = connection;
        this.circuitId = circuitId;

        this.relayCellResponseQueue = new LinkedBlockingQueue<RelayCell>();
        this.controlCellResponseQueue = new LinkedBlockingQueue<Cell>();
        this.streamMap = new HashMap<Integer, StreamImpl>();
    }

    Connection getConnection() {
        return connection;
    }

    int getCircuitId() {
        return circuitId;
    }

    // Return null on timeout or when the circuit has been destroyed
    RelayCell dequeueRelayResponseCell() {
        try {
            final long timeout = getReceiveTimeout();
            final RelayCell cell = relayCellResponseQueue.poll(timeout, TimeUnit.MILLISECONDS);
            if(cell == DESTROYED_RELAY_CELL) {
                // leave it for any other waiting thread
                relayCellResponseQueue.add(cell);
                return null;
            }
            return cell;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    /**
     * If the circuit has been destroyed, the reason, otherwise null.
     */
    String getDestroyReason() {
        return destroyReason;
    }

    private RelayCell decryptRelayCell(Cell cell) {
        for(CircuitNode node: circuit.getNodeList()) {
            if(node.decryptBackwardCell(cell)) {
                return RelayCellImpl.createFromCell(node, cell);
            }
        }
        destroyCircuit();
        throw new TorException("Could not decrypt relay cell");
    }

    // Return null on timeout or when the circuit has been destroyed
    Cell receiveControlCellResponse() {
        try {
            final long timeout = getReceiveTimeout();
            final Cell cell = controlCellResponseQueue.poll(timeout, TimeUnit.MILLISECONDS);
            if(cell == DESTROYED_CONTROL_CELL) {
                controlCellResponseQueue.add(cell);
                return null;
            }
            return cell;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }


    private long getReceiveTimeout() {
        if(circuit.getStatus().isBuilding()){
            return remainingBuildTime();
        } else{
            return CIRCUIT_RELAY_RESPONSE_TIMEOUT;
        }
    }

    private long remainingBuildTime() {
        return remainingBuildTime(circuit.getStatus().getMillisecondsElapsedSinceCreated());
    }

    /*
     * Time left to wait for a reply while the circuit is being built.
     *
     * An elapsed time of 0 means the build started less than a millisecond
     * ago, which is the normal case when the first hop is reached over an
     * already open (cached) connection: CREATE_FAST is sent immediately.
     * Treating 0 as "no time left" made the wait for CREATED_FAST return at
     * once, so every circuit over a reused connection failed with a timeout.
     */
    static long remainingBuildTime(long elapsed) {
        if(elapsed <= 0) {
            return CIRCUIT_BUILD_TIMEOUT_MS;
        }
        if(elapsed >= CIRCUIT_BUILD_TIMEOUT_MS) {
            return 0;
        }
        return CIRCUIT_BUILD_TIMEOUT_MS - elapsed;
    }

    /*
     * This is called by the cell reading thread in ConnectionImpl to deliver control cells 
     * associated with this circuit (CREATED, CREATED_FAST, or DESTROY).
     */
    void deliverControlCell(Cell cell) {
        if(cell.getCommand() == Cell.DESTROY) {
            processDestroyCell(cell.getByte());
        } else {
            controlCellResponseQueue.add(cell);
        }
    }

    private void processDestroyCell(int reason) {
        logger.debug("DESTROY cell received ("+ CellImpl.errorToDescription(reason) +") on "+ circuit);
        destroyCircuit("destroyed by relay: "+ CellImpl.errorToDescription(reason));
    }

    /* This is called by the cell reading thread in ConnectionImpl to deliver RELAY cells. */
    void deliverRelayCell(Cell cell) {
        circuit.getStatus().updateDirtyTimestamp();
        final RelayCell relayCell = decryptRelayCell(cell);
        logRelayCell("Dispatching: ", relayCell);
        switch(relayCell.getRelayCommand()) {
        case RelayCell.RELAY_EXTENDED:
        case RelayCell.RELAY_EXTENDED2:
        case RelayCell.RELAY_RESOLVED:
        case RelayCell.RELAY_TRUNCATED:
        case RelayCell.RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
        case RelayCell.RELAY_COMMAND_INTRODUCE_ACK:
        case RelayCell.RELAY_COMMAND_RENDEZVOUS2:
            relayCellResponseQueue.add(relayCell);
            break;	
        case RelayCell.RELAY_DATA:
        case RelayCell.RELAY_END:
        case RelayCell.RELAY_CONNECTED:
            processRelayDataCell(relayCell);
            break;

        case RelayCell.RELAY_SENDME:
            if(relayCell.getStreamId() != 0)
                processRelayDataCell(relayCell);
            else
                processCircuitSendme(relayCell);
            break;
        case RelayCell.RELAY_BEGIN:
        case RelayCell.RELAY_BEGIN_DIR:
        case RelayCell.RELAY_EXTEND:
        case RelayCell.RELAY_RESOLVE:
        case RelayCell.RELAY_TRUNCATE:
            destroyCircuit();
            throw new TorException("Unexpected 'forward' direction relay cell type: "+ relayCell.getRelayCommand());
        }
    }

    /* Runs in the context of the connection cell reading thread */
    private void processRelayDataCell(RelayCell cell) {
        if(cell.getRelayCommand() == RelayCell.RELAY_DATA) {
            final byte[] sendmeTag = dataCellReceived(cell.getCircuitNode());
            if(sendmeTag != null) {
                sendRelayCellTo(createSendme(cell.getCircuitNode(), sendmeTag), cell.getCircuitNode());
            }
        }

        streamLock.lock();
        try {
            final StreamImpl stream = streamMap.get(cell.getStreamId());
            // It's not unusual for the stream to not be found.  For example, if a RELAY_CONNECTED arrives after
            // the client has stopped waiting for it, the stream will never be tracked and eventually the edge node
            // will send a RELAY_END for this stream.
            if(stream != null) {
                stream.addInputCell(cell);
            }
        } finally {
            streamLock.unlock();
        }
    }

    private byte[] dataCellReceived(CircuitNode node) {
        try {
            return node.dataCellReceived();
        } catch (TorException e) {
            destroyCircuit("protocol error: "+ e.getMessage());
            throw e;
        }
    }

    /*
     * A circuit level SENDME of version 1 (authenticated): VERSION (1 byte),
     * DATA_LEN (2 bytes), DATA (the tag).  See tor-spec, "Flow control".
     */
    private RelayCell createSendme(CircuitNode node, byte[] tag) {
        final RelayCell sendme = createRelayCell(RelayCell.RELAY_SENDME, 0, node);
        sendme.putByte(CircuitNodeImpl.SENDME_VERSION_AUTHENTICATED);
        sendme.putShort(tag.length);
        sendme.putByteArray(tag);
        return sendme;
    }

    RelayCell createRelayCell(int relayCommand, int streamId, CircuitNode targetNode) {
        return new RelayCellImpl(targetNode, circuitId, streamId, relayCommand);
    }

    /*
     * The circuit's packaging window is taken while relaySendLock is held,
     * so that DATA cells reach the relay in the order in which they took
     * the window, as the digests remembered for authenticated SENDMEs
     * require.  The wait for the window to open happens without the lock:
     * the cell reading thread needs the lock to send our own SENDMEs, and
     * it must keep reading to receive the SENDMEs that open the window.
     */
    void sendRelayCellTo(RelayCell cell, CircuitNode targetNode) {
        final boolean isData = cell.getRelayCommand() == RelayCell.RELAY_DATA;
        while(true) {
            if(isData) {
                targetNode.waitForSendWindow();
            }
            relaySendLock.lock();
            try {
                final int sendWindow = isData ? targetNode.takeSendWindow() : 0;
                if(isData && sendWindow == 0) {
                    // another thread took the window first
                    continue;
                }
                logRelayCell("Sending:     ", cell);
                cell.setLength();
                targetNode.updateForwardDigest(cell);
                cell.setDigest(targetNode.getForwardDigestBytes());
                if(isData) {
                    targetNode.dataCellSent(sendWindow);
                }

                for(CircuitNode node = targetNode; node != null; node = node.getPreviousNode()){
                    node.encryptForwardCell(cell);
                }

                sendCell(cell);
                return;
            } finally {
                relaySendLock.unlock();
            }
        }
    }

    private void logRelayCell(String message, RelayCell cell) {
        logger.debug(message + cell);
    }

    void sendCell(Cell cell) {
        final CircuitStatus status = circuit.getStatus();
        if(!(status.isConnected() || status.isBuilding())){
            return;
        }
        try {
            status.updateDirtyTimestamp();
            connection.sendCell(cell);
        } catch (ConnectionIOException e) {
            destroyCircuit();
        }
    }

    void markForClose() {
        boolean shouldClose;
        streamLock.lock();
        try {
            if(isMarkedForClose) {
                return;
            }
            isMarkedForClose = true;
            shouldClose = streamMap.isEmpty();
        } finally {
            streamLock.unlock();
        }
        if(shouldClose){
            closeCircuit();
        }
    }

    boolean isMarkedForClose() {
        streamLock.lock();
        try {
            return isMarkedForClose;
        } finally {
            streamLock.unlock();
        }
    }

    private void closeCircuit() {
        logger.debug("Closing circuit "+ circuit);
        sendDestroyCell(Cell.ERROR_NONE);
        connection.removeCircuit(circuit);
        circuit.setStateDestroyed();
        isClosed = true;
    }

    void sendDestroyCell(int reason) {
        if(connection.isClosed()) {
            // The link is gone, and with it every circuit on it.
            return;
        }
        Cell destroy = CellImpl.createCell(circuitId, Cell.DESTROY);
        destroy.putByte(reason);
        try {
            connection.sendCell(destroy);
        } catch (ConnectionIOException e) {
            logger.warn("Connection IO error sending DESTROY cell: "+ e.getMessage());
        }
    }

    /*
     * A circuit level SENDME from a relay.  Version 1 SENDMEs carry the tag
     * of the DATA cell they acknowledge, which must match the one we
     * remembered when we sent it; version 0 SENDMEs (an empty payload)
     * carry none.
     */
    private void processCircuitSendme(RelayCell cell) {
        byte[] tag = null;
        if(cell.cellBytesRemaining() > 0) {
            final int version = cell.getByte();
            if(version == CircuitNodeImpl.SENDME_VERSION_AUTHENTICATED) {
                if(cell.cellBytesRemaining() < 2) {
                    rejectSendme(cell, "truncated SENDME");
                    return;
                }
                final int length = cell.getShort();
                if(length != CircuitNodeImpl.SENDME_TAG_LEN || length > cell.cellBytesRemaining()) {
                    rejectSendme(cell, "bad SENDME tag length "+ length);
                    return;
                }
                tag = new byte[length];
                cell.getByteArray(tag);
            } else if(version != 0) {
                rejectSendme(cell, "unknown SENDME version "+ version);
                return;
            }
        }
        if(!cell.getCircuitNode().processSendme(tag)) {
            rejectSendme(cell, "SENDME does not match a DATA cell we sent");
        }
    }

    private void rejectSendme(RelayCell cell, String reason) {
        logger.warn("Closing circuit "+ circuit +": "+ reason +" from "+ cell.getCircuitNode());
        sendDestroyCell(Cell.ERROR_PROTOCOL);
        destroyCircuit("protocol error: "+ reason);
    }

    void destroyCircuit() {
        destroyCircuit("closed");
    }

    void destroyCircuit(String reason) {
        streamLock.lock();
        try {
            if(isClosed) {
                return;
            }
            destroyReason = reason;
            circuit.setStateDestroyed();
            connection.removeCircuit(circuit);
            final List<StreamImpl> tmpList = new ArrayList<StreamImpl>(streamMap.values());
            for(StreamImpl s: tmpList) {
                s.close();
            }
            isClosed = true;
        } finally {
            streamLock.unlock();
        }
        controlCellResponseQueue.add(DESTROYED_CONTROL_CELL);
        relayCellResponseQueue.add(DESTROYED_RELAY_CELL);
    }

    StreamImpl createNewStream(boolean autoclose) {
        streamLock.lock();
        try {
            final int streamId = circuit.getStatus().nextStreamId();
            final StreamImpl stream = new StreamImpl(circuit, circuit.getFinalCircuitNode(), streamId, autoclose);
            streamMap.put(streamId, stream);
            return stream;
        } finally {
            streamLock.unlock();
        }
    }

    void removeStream(StreamImpl stream) {
        boolean shouldClose;
        streamLock.lock();
        try {
            streamMap.remove(stream.getStreamId());
            shouldClose = streamMap.isEmpty() && isMarkedForClose;
        } finally {
            streamLock.unlock();
        }
        if(shouldClose){
            closeCircuit();
        }
    }

    List<Stream> getActiveStreams() {
        streamLock.lock();
        try {
            return new ArrayList<Stream>(streamMap.values());
        } finally {
            streamLock.unlock();
        }
    }

    public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException {
        if((flags & DASHBOARD_STREAMS) == 0) {
            return;
        }
        for(Stream s: getActiveStreams()) {
            renderer.renderComponent(writer, flags, s);
        }
    }
}
