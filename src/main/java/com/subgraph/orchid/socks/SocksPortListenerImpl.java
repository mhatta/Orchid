package com.subgraph.orchid.socks;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.SocksPortListener;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.logging.Logger;

public class SocksPortListenerImpl implements SocksPortListener {
    private static final Logger logger = Logger.getInstance(SocksPortListenerImpl.class);

    /*
     * The most SOCKS clients served at once.  Every client takes a thread
     * (two more once its stream is open), so without a limit a flood of
     * connections exhausts the threads and memory of the whole JVM.
     */
    static final int MAX_CONCURRENT_CLIENTS = 512;
    private final Semaphore clientSlots = new Semaphore(MAX_CONCURRENT_CLIENTS);
    private final Set<Integer> listeningPorts = new HashSet<Integer>();
    private final Map<Integer, AcceptTask> acceptThreads = new HashMap<Integer, AcceptTask>();
    private final TorConfig config;
    private final CircuitManager circuitManager;
    private final ExecutorService executor;
    private boolean isStopped;

    public SocksPortListenerImpl(TorConfig config, CircuitManager circuitManager) {
        this.config = config;
        this.circuitManager = circuitManager;
        executor = Executors.newCachedThreadPool();
    }

    @Override
    public void addListeningPort(int port) {
        if(port <= 0 || port > 65535) {
            throw new TorException("Illegal listening port: "+ port);
        }

        synchronized(listeningPorts) {
            if(isStopped) {
                throw new IllegalStateException("Cannot add listening port because Socks proxy has been stopped");
            }
            if(listeningPorts.contains(port))
                return;
            listeningPorts.add(port);
            try {
                startListening(port);
                logger.debug("Listening for SOCKS connections on port "+ port);
            } catch (IOException e) {
                listeningPorts.remove(port);
                throw new TorException("Failed to listen on port "+ port +" : "+ e.getMessage());
            }
        }

    }

    @Override
    public void stop() {
        synchronized (listeningPorts) {
            for(AcceptTask t: acceptThreads.values()) {
                t.stop();
            }
            executor.shutdownNow();
            isStopped = true;
        }
    }

    private void startListening(int port) throws IOException {
        final AcceptTask task = new AcceptTask(port);
        acceptThreads.put(port, task);
        executor.execute(task);
    }

    private Runnable newClientSocket(final Socket s) {
        final Runnable task = new SocksClientTask(config, s, circuitManager);
        return new Runnable() {
            public void run() {
                try {
                    task.run();
                } finally {
                    clientSlots.release();
                }
            }
        };
    }

    private void acceptClient(Socket s) {
        if(!clientSlots.tryAcquire()) {
            logger.warn("Too many SOCKS clients (limit "+ MAX_CONCURRENT_CLIENTS +"), refusing a connection");
            closeQuietly(s);
            return;
        }
        try {
            executor.execute(newClientSocket(s));
        } catch(RuntimeException e) {
            clientSlots.release();
            closeQuietly(s);
            throw e;
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException e) {
            //swallow
        }
    }

    /*
     * The SOCKS listener binds to the loopback address unless the
     * configuration names another one.  Binding to every interface, as
     * Orchid did before, let any host that can reach the port use it as an
     * open Tor proxy.
     */
    private InetAddress getListenAddress() throws IOException {
        final String address = config.getSocksListenAddress();
        if(address == null || address.trim().isEmpty()) {
            return InetAddress.getLoopbackAddress();
        }
        return InetAddress.getByName(address.trim());
    }

    private class AcceptTask implements Runnable {
        private final ServerSocket socket;
        private final int port;
        private volatile boolean stopped;

        AcceptTask(int port) throws IOException {
            final InetAddress address = getListenAddress();
            this.socket = new ServerSocket(port, 50, address);
            if(!address.isLoopbackAddress()) {
                logger.warn("SOCKS listener on port "+ port +" is bound to "+ address.getHostAddress() +
                        ", not to the loopback address: other hosts that can reach it can use it as a Tor proxy");
            }
            this.port = port;
        }

        void stop() {
            stopped = true;
            try {
                socket.close();
            } catch (IOException e) { 
                //swallow
            }
        }

        @Override
        public void run() {
            try {
                runAcceptLoop();
            } catch (IOException e) {
                if(!stopped) {
                    logger.warn("System error accepting SOCKS socket connections: "+ e.getMessage());
                }
            } finally {
                synchronized (listeningPorts) {
                    listeningPorts.remove(port);
                    acceptThreads.remove(port);
                }
            }
        }

        private void runAcceptLoop() throws IOException {
            while(!Thread.interrupted() && !stopped) {
                acceptClient(socket.accept());
            }
        }
    }
}
