package com.subgraph.orchid.connections;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLSocket;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionFailedException;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionIOException;
import com.subgraph.orchid.ConnectionTimeoutException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.TorInitializationTracker;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.dashboard.DashboardRenderable;
import com.subgraph.orchid.dashboard.DashboardRenderer;
import com.subgraph.orchid.logging.Logger;

/**
 * This class represents a transport link between two onion routers or
 * between an onion proxy and an entry router.
 *
 */
public class ConnectionImpl implements Connection, DashboardRenderable {
    private static final Logger logger = Logger.getInstance(ConnectionImpl.class);
    private final static int CONNECTION_IDLE_TIMEOUT = 5 * 60 * 1000; // 5 minutes
    private final static int DEFAULT_CONNECT_TIMEOUT = 5000;
    private final static Cell connectionClosedSentinel = CellImpl.createCell(0, 0);

    private final TorConfig config;
    private final SSLSocket socket;
    private InputStream input;
    private OutputStream output;
    private final Router router;
    private final Map<Integer, Circuit> circuitMap;
    private final BlockingQueue<Cell> connectionControlCells;
    private final TorInitializationTracker initializationTracker;
    private final boolean isDirectoryConnection;

    /*
     * Circuit ids are 4 bytes wide (link protocol 4 and later), and the side
     * that opened the connection sets the most significant bit (tor-spec
     * section 5.1.1).  Only the lower 31 bits are counted here.
     */
    private final static int CIRCID_INITIATOR_BIT = 0x80000000;
    private final static int CIRCID_COUNTER_MAX = 0x7FFFFFFF;

    /*
     * The link protocol version agreed on in the VERSIONS exchange, or 0
     * before it has been agreed on.  It is set by the cell reading thread
     * as soon as the VERSIONS cell arrives, because the width of the
     * circuit id of the cells that follow depends on it.
     */
    private volatile int linkProtocolVersion;

    private int currentId = 1;
    private boolean isConnected;
    private volatile boolean isClosed;
    private final Thread readCellsThread;
    private final ReentrantLock connectLock = Threading.lock("connect");
    private final ReentrantLock circuitsLock = Threading.lock("circuits");
    private final ReentrantLock outputLock = Threading.lock("output");
    private final AtomicLong lastActivity = new AtomicLong();


    public ConnectionImpl(TorConfig config, SSLSocket socket, Router router, TorInitializationTracker tracker, boolean isDirectoryConnection) {
        this.config = config;
        this.socket = socket;
        this.router = router;
        this.circuitMap = new HashMap<Integer, Circuit>();
        this.readCellsThread = new Thread(createReadCellsRunnable());
        this.readCellsThread.setDaemon(true);
        this.connectionControlCells = new LinkedBlockingQueue<Cell>();
        this.initializationTracker = tracker;
        this.isDirectoryConnection = isDirectoryConnection;
        initializeCurrentCircuitId();
    }

    private void initializeCurrentCircuitId() {
        final TorRandom random = new TorRandom();
        currentId = random.nextInt(CIRCID_COUNTER_MAX) + 1;
    }

    @Override
    public Router getRouter() {
        return router;
    }

    @Override
    public boolean isClosed() {
        return isClosed;
    }

    @Override
    public int bindCircuit(Circuit circuit) {
        circuitsLock.lock();
        try {
            while(circuitMap.containsKey(currentId | CIRCID_INITIATOR_BIT)) {
                incrementNextId();
            }
            final int id = currentId | CIRCID_INITIATOR_BIT;
            incrementNextId();
            circuitMap.put(id, circuit);
            return id;
        } finally {
            circuitsLock.unlock();
        }
    }

    private void incrementNextId() {
        currentId++;
        if(currentId > CIRCID_COUNTER_MAX || currentId <= 0){
                currentId = 1;
        }
    }

    void connect() throws ConnectionFailedException, ConnectionTimeoutException, ConnectionHandshakeException {
        connectLock.lock();
        try {
            if(isConnected) {
                return;
            }
            try {
                doConnect();
            } catch (SocketTimeoutException e) {
                throw new ConnectionTimeoutException();
            } catch (IOException e) {
                throw new ConnectionFailedException(e.getClass().getName() + " : "+ e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ConnectionHandshakeException("Handshake interrupted");
            } catch (ConnectionHandshakeException e) {
                throw e;
            } catch (ConnectionIOException e) {
                throw new ConnectionFailedException(e.getMessage());
            }
            isConnected = true;
        } finally {
            connectLock.unlock();
        }
    }

    private void doConnect() throws IOException, InterruptedException, ConnectionIOException {
        connectSocket();
        final ConnectionHandshake handshake = ConnectionHandshake.createHandshake(config, this, socket);
        input = socket.getInputStream();
        output = socket.getOutputStream();
        readCellsThread.start();
        handshake.runHandshake();
        updateLastActivity();
    }

    private void connectSocket() throws IOException {
        if(initializationTracker != null) {
            if(isDirectoryConnection) {
                initializationTracker.notifyEvent(Tor.BOOTSTRAP_STATUS_CONN_DIR);
            } else {
                initializationTracker.notifyEvent(Tor.BOOTSTRAP_STATUS_CONN_OR);
            }
        }

        socket.connect(routerToSocketAddress(router), DEFAULT_CONNECT_TIMEOUT);

        if(initializationTracker != null) {
            if(isDirectoryConnection) {
                initializationTracker.notifyEvent(Tor.BOOTSTRAP_STATUS_HANDSHAKE_DIR);
            } else {
                initializationTracker.notifyEvent(Tor.BOOTSTRAP_STATUS_HANDSHAKE_OR);
            }
        }
    }

    private SocketAddress routerToSocketAddress(Router router) {
        final InetAddress address = router.getAddress().toInetAddress();
        return new InetSocketAddress(address, router.getOnionPort());
    }

    public void sendCell(Cell cell) throws ConnectionIOException  {
        if(!socket.isConnected()) {
            throw new ConnectionIOException("Cannot send cell because connection is not connected");
        }
        updateLastActivity();
        outputLock.lock();
        try {
            try {
                output.write(CellImpl.toWireBytes(cell, wireCircIdLengthFor(cell)));
            } catch (IOException e) {
                logger.debug("IOException writing cell to connection "+ e.getMessage());
                closeSocket();
                throw new ConnectionIOException(e.getClass().getName() + " : "+ e.getMessage());
            }
        } finally {
            outputLock.unlock();
        }
    }

    private Cell recvCell() throws ConnectionIOException {
        try {
            return CellImpl.readFromInputStream(input, wireCircIdLength());
        } catch(EOFException e) {
            closeSocket();
            throw new ConnectionIOException();
        } catch (IOException e) {
            if(!isClosed) {
                logger.debug("IOException reading cell from connection "+ this + " : "+ e.getMessage());
                closeSocket();
            }
            throw new ConnectionIOException(e.getClass().getName() + " " + e.getMessage());
        }
    }

    /**
     * The link protocol version agreed on with the relay, or 0 if the
     * VERSIONS exchange has not completed or found no common version.
     */
    int getLinkProtocolVersion() {
        return linkProtocolVersion;
    }

    /* The width of the circuit id field of cells on this connection. */
    private int wireCircIdLength() {
        return (linkProtocolVersion >= 4) ? Cell.CIRCID_LEN : Cell.WIRE_CIRCID_LEN_V3;
    }

    /* VERSIONS cells always have a 2 byte circuit id (tor-spec section 4.1). */
    private int wireCircIdLengthFor(Cell cell) {
        return (cell.getCommand() == Cell.VERSIONS) ? Cell.WIRE_CIRCID_LEN_V3 : wireCircIdLength();
    }

    /*
     * Runs in the cell reading thread, before the next cell is read: record
     * the link protocol version so that the following cells are read with
     * the right circuit id width.  The handshake checks the result.
     */
    private void processVersionsCell(Cell cell) {
        if(linkProtocolVersion == 0) {
            linkProtocolVersion = ConnectionHandshake.chooseLinkProtocolVersion(ConnectionHandshake.readVersions(cell));
        }
    }

    void closeSocket() {
        try {
            logger.debug("Closing connection to "+ this);
            isClosed = true;
            socket.close();
            isConnected = false;
        } catch (IOException e) {
            logger.warn("Error closing socket: "+ e.getMessage());
        }
    }

    private Runnable createReadCellsRunnable() {
        return new Runnable() {
            public void run() {
                try {
                    readCellsLoop();
                } catch(Exception e) {
                    logger.warn("Unhandled exception processing incoming cells on connection "+ e, e);
                }
            }
        };
    }

    private void readCellsLoop() {
        while(!Thread.interrupted()) {
            try {
                processCell( recvCell() );
            } catch(ConnectionIOException e) {
                connectionControlCells.add(connectionClosedSentinel);
                notifyCircuitsLinkClosed();
                return;
            } catch(TorException e) {
                logger.warn("Unhandled Tor exception reading and processing cells: "+ e.getMessage(), e);
            }
        }
    }

    /*
     * Every circuit on a closed connection is gone.  Destroy them so that
     * threads waiting on them (a circuit build, a stream read) notice now
     * instead of when their timeout expires.
     */
    private void notifyCircuitsLinkClosed() {
        final List<Circuit> circuits;
        circuitsLock.lock();
        try {
            circuits = new ArrayList<Circuit>(circuitMap.values());
        } finally {
            circuitsLock.unlock();
        }
        for(Circuit c: circuits) {
            try {
                c.destroyCircuit();
            } catch(RuntimeException e) {
                logger.debug("Exception destroying circuit after connection to "+ router + " closed: "+ e);
            }
        }
    }

    Cell readConnectionControlCell() throws ConnectionIOException {
        try {
            return connectionControlCells.take();
        } catch (InterruptedException e) {
            closeSocket();
            throw new ConnectionIOException();
        }
    }

    private void processCell(Cell cell) {
        updateLastActivity();
        final int command = cell.getCommand();

        if(command == Cell.RELAY) {
            processRelayCell(cell);
            return;
        }

        switch(command) {
        case Cell.VERSIONS:
            processVersionsCell(cell);
            connectionControlCells.add(cell);
            break;
        case Cell.NETINFO:
        case Cell.CERTS:
        case Cell.AUTH_CHALLENGE:
            connectionControlCells.add(cell);
            break;

        case Cell.CREATED2:
        case Cell.CREATED_FAST:
        case Cell.DESTROY:
            processControlCell(cell);
            break;
        default:
            // Ignore everything else, including the PADDING and VPADDING
            // cells relays send on link protocol 5 connections.
            break;
        }
    }

    private void processRelayCell(Cell cell) {
        Circuit circuit;
        circuitsLock.lock();
        try {
            circuit = circuitMap.get(cell.getCircuitId());
            if(circuit == null) {
                logger.warn("Could not deliver relay cell for circuit id = "+ Integer.toHexString(cell.getCircuitId()) +" on connection "+ this +". Circuit not found");
                return;
            }
        } finally {
            circuitsLock.unlock();
        }

        circuit.deliverRelayCell(cell);
    }

    private void processControlCell(Cell cell) {
        Circuit circuit;
        circuitsLock.lock();
        try {
            circuit = circuitMap.get(cell.getCircuitId());
        } finally {
            circuitsLock.unlock();
        }

        if(circuit != null) {
            circuit.deliverControlCell(cell);
        }
    }

    void idleCloseCheck() {
        circuitsLock.lock();
        try {
            final boolean needClose =  (!isClosed && circuitMap.isEmpty() && getIdleMilliseconds() > CONNECTION_IDLE_TIMEOUT);
            if(needClose) {
                logger.debug("Closing connection to "+ this +" on idle timeout");
                closeSocket();
            }
        } finally {
            circuitsLock.unlock();
        }
    }

    private void updateLastActivity() {
        lastActivity.set(System.currentTimeMillis());
    }

    private long getIdleMilliseconds() {
        if(lastActivity.get() == 0) {
            return 0;
        }
        return System.currentTimeMillis() - lastActivity.get();
    }

    @Override
    public void removeCircuit(Circuit circuit) {
        circuitsLock.lock();
        try {
            circuitMap.remove(circuit.getCircuitId());
        } finally {
            circuitsLock.unlock();
        }
    }

    @Override
    public String toString() {
        return "!" + router.getNickname() + "!";
    }

    @Override
    public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) throws IOException {
        final int circuitCount;
        circuitsLock.lock();
        try {
            circuitCount = circuitMap.size();
        } finally {
            circuitsLock.unlock();
        }
        if(circuitCount == 0 && (flags & DASHBOARD_CONNECTIONS_VERBOSE) == 0) {
            return;
        }
        writer.print("  [Connection router="+ router.getNickname());
        writer.print(" circuits="+ circuitCount);
        writer.print(" idle="+ (getIdleMilliseconds()/1000) + "s");
        writer.println("]");
    }
}
