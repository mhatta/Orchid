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

    SocksClientTask(TorConfig config, Socket socket, CircuitManager circuitManager) {
        this.config = config;
        this.socket = socket;
        this.circuitManager = circuitManager;
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
     * A client has SocksTimeout to send its request; a client that connects
     * and then says nothing would otherwise hold a thread for ever.  The
     * timeout is lifted once the stream is open (runOpenConnection).
     */
    private void setNegotiationTimeout() {
        final long timeout = config.getSocksTimeout();
        if(timeout <= 0) {
            return;
        }
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
            if(!request.isConnectRequest()) {
                logger.warn("Non connect command ("+ request.getCommandCode() + ")");
                request.sendError(true);
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
            return circuitManager.openExitStreamTo(request.getHostname(), request.getPort(), request.getIsolationKey());
        } else {
            logger.debug("SOCKS CONNECT request to "+ request.getTarget());
            return circuitManager.openExitStreamTo(request.getAddress(), request.getPort(), request.getIsolationKey());
        }
    }

    /*
     * Someone pointed a web browser (or another HTTP client) at the SOCKS
     * port.  Tell them, instead of throwing and leaving the socket open.
     */
    private void sendHttpPage() {
        final String body = "This is a SOCKS proxy, not an HTTP proxy.\r\n" +
                "Configure your application to use it as a SOCKS5 proxy.\r\n";
        final String response = "HTTP/1.0 501 Tor is not an HTTP Proxy\r\n" +
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
