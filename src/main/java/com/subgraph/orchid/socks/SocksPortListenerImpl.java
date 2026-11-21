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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.SocksPortListener;
import com.subgraph.orchid.Threading;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.logging.Logger;

public class SocksPortListenerImpl implements SocksPortListener {
    private static final Logger logger = Logger.getInstance(SocksPortListenerImpl.class);

    /*
     * The most SOCKS clients served at once.  Every client takes a thread
     * (two more once its stream is open), so without a limit a flood of
     * connections exhausts the threads and memory of the whole JVM.  256
     * clients are up to 768 threads, already a lot for a small phone.
     */
    static final int MAX_CONCURRENT_CLIENTS = 256;
    private final Semaphore clientSlots = new Semaphore(MAX_CONCURRENT_CLIENTS);

    /*
     * The most clients that have connected but not yet sent their whole
     * request, and how long they have to send it.  On Android every app on
     * the device can connect to the loopback port, whether or not it knows
     * the SOCKS password; without these limits an app that opened a few
     * hundred connections and sent nothing stopped the proxy for everyone
     * else for SocksTimeout (two minutes by default).  A real client sends
     * its request at once, so ten seconds is plenty.  The time is for the
     * whole request, not for each read, so a client cannot keep its slot by
     * sending one byte now and then.
     */
    static final int MAX_HANDSHAKING_CLIENTS = 64;
    static final long HANDSHAKE_TIMEOUT_MS = 10 * 1000;
    private final Semaphore handshakeSlots = new Semaphore(MAX_HANDSHAKING_CLIENTS);
    private final ScheduledExecutorService handshakeWatchdog = Threading.newScheduledPool("SOCKS handshake watchdog");
    private final Set<Integer> listeningPorts = new HashSet<Integer>();
    /* The ports of listeningPorts that are HTTP tunnel ports, not SOCKS ports. */
    private final Set<Integer> httpTunnelPorts = new HashSet<Integer>();
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
        addPort(port, false);
    }

    /**
     * Listen on <code>port</code> for HTTP CONNECT requests (Tor's
     * HTTPTunnelPort), on the same address as the SOCKS ports and with the
     * same limits on clients: see {@code HttpTunnelClientTask}.
     */
    @Override
    public void addHttpTunnelPort(int port) {
        addPort(port, true);
    }

    private void addPort(int port, boolean httpTunnel) {
        if(port <= 0 || port > 65535) {
            throw new TorException("Illegal listening port: "+ port);
        }

        synchronized(listeningPorts) {
            if(isStopped) {
                throw new IllegalStateException("Cannot add listening port because Socks proxy has been stopped");
            }
            if(listeningPorts.contains(port)) {
                if(httpTunnelPorts.contains(port) != httpTunnel) {
                    throw new TorException("Port "+ port +" is already used for "+ (httpTunnel ? "SOCKS" : "HTTP CONNECT"));
                }
                return;
            }
            listeningPorts.add(port);
            if(httpTunnel) {
                httpTunnelPorts.add(port);
            }
            try {
                startListening(port, httpTunnel);
                logger.debug("Listening for SOCKS connections on port "+ port);
            } catch (IOException e) {
                listeningPorts.remove(port);
                httpTunnelPorts.remove(port);
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
            handshakeWatchdog.shutdownNow();
            isStopped = true;
        }
    }

    private void startListening(int port, boolean httpTunnel) throws IOException {
        final AcceptTask task = new AcceptTask(port, httpTunnel);
        acceptThreads.put(port, task);
        executor.execute(task);
    }

    /* The time a client has to send its whole request. */
    long getHandshakeTimeout() {
        final long t = config.getSocksTimeout();
        return (t > 0) ? Math.min(t, HANDSHAKE_TIMEOUT_MS) : HANDSHAKE_TIMEOUT_MS;
    }

    /*
     * Holds a handshake slot until the client has sent its request, and
     * closes the socket if it has not done so in time.
     */
    private final class Handshake implements Runnable {
        private final AtomicBoolean done = new AtomicBoolean();
        private volatile ScheduledFuture<?> closer;

        void start(final Socket s) {
            closer = handshakeWatchdog.schedule(new Runnable() {
                public void run() {
                    if(!done.get()) {
                        logger.debug("SOCKS client sent no complete request in "+ getHandshakeTimeout() +" ms, closing");
                        closeQuietly(s);
                    }
                }
            }, getHandshakeTimeout(), TimeUnit.MILLISECONDS);
        }

        /* The request has been read (or the client is gone). */
        public void run() {
            if(done.compareAndSet(false, true)) {
                final ScheduledFuture<?> c = closer;
                if(c != null) {
                    c.cancel(false);
                }
                handshakeSlots.release();
            }
        }
    }

    private Runnable newClientSocket(final Socket s, final Handshake handshake, boolean httpTunnel) {
        final Runnable task = httpTunnel
                ? new HttpTunnelClientTask(config, s, circuitManager, handshake)
                : new SocksClientTask(config, s, circuitManager, handshake);
        return new Runnable() {
            public void run() {
                try {
                    task.run();
                } finally {
                    handshake.run();
                    clientSlots.release();
                }
            }
        };
    }

    private void acceptClient(Socket s, boolean httpTunnel) {
        if(!clientSlots.tryAcquire()) {
            logger.warn("Too many SOCKS clients (limit "+ MAX_CONCURRENT_CLIENTS +"), refusing a connection");
            closeQuietly(s);
            return;
        }
        if(!handshakeSlots.tryAcquire()) {
            clientSlots.release();
            logger.warn("Too many SOCKS clients that have not sent a request (limit "+ MAX_HANDSHAKING_CLIENTS +"), refusing a connection");
            closeQuietly(s);
            return;
        }
        final Handshake handshake = new Handshake();
        try {
            handshake.start(s);
            executor.execute(newClientSocket(s, handshake, httpTunnel));
        } catch(RuntimeException e) {
            handshake.run();
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
        private final boolean httpTunnel;
        private volatile boolean stopped;

        AcceptTask(int port, boolean httpTunnel) throws IOException {
            final InetAddress address = getListenAddress();
            this.socket = new ServerSocket(port, 50, address);
            this.httpTunnel = httpTunnel;
            if(!address.isLoopbackAddress()) {
                logger.warn((httpTunnel ? "HTTP tunnel" : "SOCKS") +" listener on port "+ port +" is bound to "+ address.getHostAddress() +
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
                    httpTunnelPorts.remove(port);
                    acceptThreads.remove(port);
                }
            }
        }

        private void runAcceptLoop() throws IOException {
            while(!Thread.interrupted() && !stopped) {
                acceptClient(socket.accept(), httpTunnel);
            }
        }
    }
}
