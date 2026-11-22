package com.subgraph.orchid.socks;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.logging.Logger;

public class SocksClientTask implements Runnable {
    private static final Logger logger = Logger.getInstance(SocksClientTask.class);
	
    private final TorConfig config;
    private final Socket socket;
    private final CircuitManager circuitManager;
    /* Called once the request has been read: see SocksPortListenerImpl.Handshake. */
    private final Runnable requestRead;
    private final ProxyCounters counters;

    SocksClientTask(TorConfig config, Socket socket, CircuitManager circuitManager) {
        this(config, socket, circuitManager, null);
    }

    SocksClientTask(TorConfig config, Socket socket, CircuitManager circuitManager, Runnable requestRead) {
        this(config, socket, circuitManager, requestRead, new ProxyCounters());
    }

    SocksClientTask(TorConfig config, Socket socket, CircuitManager circuitManager, Runnable requestRead, ProxyCounters counters) {
        this.config = config;
        this.socket = socket;
        this.circuitManager = circuitManager;
        this.requestRead = requestRead;
        this.counters = counters;
    }

    @Override
    public void run() {
        try {
            setNegotiationTimeout();
            final int version = readByte();
            dispatchRequest(version);
        } catch(RuntimeException e) {
            logger.warn("Unexpected error serving SOCKS client: "+ e);
        } finally {
            closeSocket();
        }
    }

    /*
     * Each read of the request waits at most HANDSHAKE_TIMEOUT_MS (or
     * SocksTimeout, if shorter); the listener also limits the time for the
     * whole request.  The timeout is lifted once the stream is open
     * (runOpenConnection).
     */
    private void setNegotiationTimeout() {
        final long socksTimeout = config.getSocksTimeout();
        final long timeout = (socksTimeout > 0) ? Math.min(socksTimeout, SocksPortListenerImpl.HANDSHAKE_TIMEOUT_MS) : SocksPortListenerImpl.HANDSHAKE_TIMEOUT_MS;
        try {
            socket.setSoTimeout((int) Math.min(timeout, Integer.MAX_VALUE));
        } catch (SocketException e) {
            logger.debug("Could not set the SOCKS negotiation timeout: "+ e.getMessage());
        }
    }

    private void clearNegotiationTimeout() {
        try {
            socket.setSoTimeout(0);
        } catch (SocketException e) {
            logger.debug("Could not clear the SOCKS negotiation timeout: "+ e.getMessage());
        }
    }

    private int readByte() {
        try {
            return socket.getInputStream().read();
        } catch (IOException e) {
            logger.warn("IO error reading version byte: "+ e.getMessage());
            return -1;
        }
    }

    private void dispatchRequest(int versionByte) {
        switch(versionByte) {
        case 'H':
        case 'G':
        case 'P':
        case 'C':
            // HEAD, GET, POST, PUT, and CONNECT from a client set up to use an HTTP proxy
            sendHttpPage();
            break;
        case 4:
            processRequest(new Socks4Request(config, socket));
            break;
        case 5:
            processRequest(new Socks5Request(config, socket));
            break;
        default:
            // fall through, do nothing
            break;
        }	
    }

    private void processRequest(SocksRequest request) {
        try {
            request.readRequest();
            if(requestRead != null) {
                requestRead.run();
            }
            if(!request.isConnectRequest()) {
                logger.warn("Non connect command ("+ request.getCommandCode() + ")");
                request.sendError(true);
                return;
            }
            final boolean refuse = request.isAddressOnly() && ProxyAuthentication.refuseAddressOnly(config);
            counters.record(request.getProfile(), request.isAddressOnly(), refuse);
            if(refuse) {
                logger.info("SOCKS request with an address only refused (SafeSocks)");
                request.sendError(false);
                return;
            }

            try {
                final Stream stream = openConnectStream(request);
                logger.debug("SOCKS CONNECT to "+ request.getTarget()+ " completed");
                request.sendSuccess();
                runOpenConnection(stream);
            } catch (InterruptedException e) {
                logger.info("SOCKS CONNECT to "+ request.getTarget() + " was thread interrupted");
                Thread.currentThread().interrupt();
                request.sendError(false);
            } catch (TimeoutException e) {
                logger.info("SOCKS CONNECT to "+ request.getTarget() + " timed out");
                request.sendError(false);
            } catch (OpenFailedException e) {
                logger.info("SOCKS CONNECT to "+ request.getTarget() + " failed: "+ e.getMessage());
                request.sendConnectionRefused();
            }
        } catch (SocksRequestException e) {
            if(request.isAddressOnly()) {
                // An IPv6 address, refused as unsupported
                counters.record(request.getProfile(), true, false);
            }
            logger.warn("Failure reading SOCKS request: "+ e.getMessage());
            try {
                request.sendError(false);
                socket.close();
            } catch (Exception ignore) {
                //swallow
            }
        } 
    }


    private void runOpenConnection(Stream stream) {
        clearNegotiationTimeout();
        SocksStreamConnection.runConnection(socket, stream);
    }

    private Stream openConnectStream(SocksRequest request) throws InterruptedException, TimeoutException, OpenFailedException {
        if(request.hasHostname()) {
            logger.debug("SOCKS CONNECT request to "+ request.getTarget());
            return circuitManager.openExitStreamTo(request.getHostname(), request.getPort(), request.getStreamIsolationKey());
        } else {
            logger.debug("SOCKS CONNECT request to "+ request.getTarget());
            return circuitManager.openExitStreamTo(request.getAddress(), request.getPort(), request.getStreamIsolationKey());
        }
    }

    /*
     * Someone pointed a web browser (or another HTTP client) at the SOCKS
     * port.  Answer, instead of throwing and leaving the socket open, but
     * with a plain status: Tor's "Tor is not an HTTP Proxy" would tell any
     * program that probes local ports (on Android, every app) that a Tor
     * client runs here.
     */
    private void sendHttpPage() {
        final String body = "Not Implemented\r\n";
        final String response = "HTTP/1.0 501 Not Implemented\r\n" +
                "Content-Type: text/plain; charset=us-ascii\r\n" +
                "Content-Length: "+ body.length() + "\r\n" +
                "Connection: close\r\n\r\n" + body;
        try {
            socket.getOutputStream().write(response.getBytes("US-ASCII"));
            socket.getOutputStream().flush();
        } catch (IOException e) {
            logger.debug("Error sending HTTP response to SOCKS port: "+ e.getMessage());
        }
    }

    private void closeSocket() {
        try {
            socket.close();
        } catch (IOException e) {
            logger.warn("Error closing SOCKS socket: "+ e.getMessage());
        }
    }
}
