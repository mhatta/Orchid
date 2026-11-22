package com.subgraph.orchid.socks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.logging.Logger;

/**
 * One client of an HTTP tunnel port (Tor's HTTPTunnelPort): a client that
 * uses Orchid as an HTTP proxy and asks for a tunnel with CONNECT
 * (RFC 9110, section 9.3.6).  Other methods are refused: Orchid is not a
 * full HTTP proxy, and forwarding plain HTTP requests would mean reading
 * and rewriting them.
 *
 * <p>The user name and password of a <code>Proxy-Authorization: Basic</code>
 * header isolate the streams as the SOCKS 5 user name and password do: the
 * same credentials give the same isolation key on both ports, as in Tor
 * (without IsolateClientProtocol).  If a SOCKS password or password
 * profiles are set ({@link TorConfig#setSocksPassword(String)},
 * {@link TorConfig#setSocksPasswords(java.util.Map)}), one of them is
 * required here too, and a client without it gets "407 Proxy
 * Authentication Required".  With SafeSocks, a CONNECT to an IP address
 * gets "403 Forbidden".
 */
final class HttpTunnelClientTask implements Runnable {
    private static final Logger logger = Logger.getInstance(HttpTunnelClientTask.class);
    private static final Charset LATIN1 = Charset.forName("ISO-8859-1");

    /* The most bytes of request line and headers read before giving up. */
    static final int MAX_HEADER_BYTES = 8192;

    private final TorConfig config;
    private final Socket socket;
    private final CircuitManager circuitManager;
    private final Runnable requestRead;
    private final ProxyCounters counters;

    HttpTunnelClientTask(TorConfig config, Socket socket, CircuitManager circuitManager, Runnable requestRead) {
        this(config, socket, circuitManager, requestRead, new ProxyCounters());
    }

    HttpTunnelClientTask(TorConfig config, Socket socket, CircuitManager circuitManager, Runnable requestRead, ProxyCounters counters) {
        this.config = config;
        this.socket = socket;
        this.circuitManager = circuitManager;
        this.requestRead = requestRead;
        this.counters = counters;
    }

    /* A request that cannot be served; the message is the status line's reason and body. */
    static class HttpError extends Exception {
        private static final long serialVersionUID = 1L;
        final int status;
        final String reason;
        HttpError(int status, String reason, String detail) {
            super(detail);
            this.status = status;
            this.reason = reason;
        }
    }

    /* A parsed CONNECT request. */
    static final class Request {
        final String host;
        final int port;
        final String isolationKey;
        /* The password profile: see ProxyAuthentication.authenticate(). */
        final String profile;
        /* An IPv6 address, which cannot be served yet; host is null. */
        final boolean ipv6;
        Request(String host, int port, String isolationKey, String profile, boolean ipv6) {
            this.host = host;
            this.port = port;
            this.isolationKey = isolationKey;
            this.profile = profile;
            this.ipv6 = ipv6;
        }

        /* An IP address instead of a host name: see ProxyStatistics. */
        boolean isAddressOnly() {
            return ipv6 || ProxyAuthentication.isAddressLiteral(host);
        }
    }

    @Override
    public void run() {
        try {
            setReadTimeout(Math.min(positive(config.getSocksTimeout()), SocksPortListenerImpl.HANDSHAKE_TIMEOUT_MS));
            final Request request;
            try {
                request = parse(readHeader(socket.getInputStream()), config);
            } finally {
                if(requestRead != null) {
                    requestRead.run();
                }
            }
            final boolean refuse = request.isAddressOnly() && !request.ipv6 && ProxyAuthentication.refuseAddressOnly(config);
            counters.record(request.profile, request.isAddressOnly(), refuse);
            if(request.ipv6) {
                throw new HttpError(400, "Bad Request", "IPv6 addresses are not supported.");
            }
            if(refuse) {
                throw new HttpError(403, "Forbidden", "Give a host name, not an address.");
            }
            serve(request);
        } catch(HttpError e) {
            logger.info("HTTP tunnel request refused: "+ e.status +" "+ e.getMessage());
            sendError(e);
        } catch(IOException e) {
            logger.debug("Error reading HTTP tunnel request: "+ e.getMessage());
        } catch(RuntimeException e) {
            logger.warn("Unexpected error serving HTTP tunnel client: "+ e);
        } finally {
            closeSocket();
        }
    }

    private static long positive(long t) {
        return t > 0 ? t : Long.MAX_VALUE;
    }

    private void serve(Request request) throws HttpError, IOException {
        final String target = config.getSafeLogging() ? "[scrubbed]:"+ request.port : request.host +":"+ request.port;
        final Stream stream;
        try {
            stream = circuitManager.openExitStreamTo(request.host, request.port,
                    SocksRequest.isolationKeyFor(config, request.isolationKey, request.host));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new HttpError(503, "Service Unavailable", "interrupted");
        } catch (TimeoutException e) {
            logger.info("HTTP CONNECT to "+ target +" timed out");
            throw new HttpError(504, "Gateway Timeout", "The Tor stream timed out.");
        } catch (OpenFailedException e) {
            logger.info("HTTP CONNECT to "+ target +" failed: "+ e.getMessage());
            throw new HttpError(502, "Bad Gateway", "The Tor stream could not be opened.");
        }
        logger.debug("HTTP CONNECT to "+ target +" completed");
        socket.getOutputStream().write("HTTP/1.0 200 Connection established\r\n\r\n".getBytes(LATIN1));
        socket.getOutputStream().flush();
        setReadTimeout(0);
        SocksStreamConnection.runConnection(socket, stream);
    }

    /*
     * Reads the request line and headers, up to and including the empty
     * line, and not a byte more: what follows belongs to the tunnel.
     */
    static String readHeader(InputStream in) throws IOException, HttpError {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int last4 = 0;
        while(true) {
            final int c = in.read();
            if(c == -1) {
                throw new IOException("end of stream in the HTTP request header");
            }
            out.write(c);
            last4 = (last4 << 8) | c;
            if(last4 == 0x0d0a0d0a || (last4 & 0xffff) == 0x0a0a) {
                return new String(out.toByteArray(), LATIN1);
            }
            if(out.size() >= MAX_HEADER_BYTES) {
                throw new HttpError(431, "Request Header Fields Too Large", "The request header is too long.");
            }
        }
    }

    static Request parse(String header, TorConfig config) throws HttpError {
        final String[] lines = header.split("\r?\n");
        final String[] requestLine = lines[0].split(" ");
        if(requestLine.length != 3 || !requestLine[2].startsWith("HTTP/1.")) {
            throw new HttpError(400, "Bad Request", "This is an HTTP tunnel (CONNECT) proxy; the request is not HTTP.");
        }
        if(!requestLine[0].equals("CONNECT")) {
            throw new HttpError(405, "Method Not Allowed",
                    "Only CONNECT is supported.");
        }
        final String authority = requestLine[1];
        /* An IPv6 address ("[::1]:443") is refused once the credentials are read (see run()), so that it is counted. */
        final boolean ipv6 = authority.startsWith("[");
        final int colon = authority.lastIndexOf(':');
        if(colon <= 0 || colon == authority.length() - 1) {
            throw new HttpError(400, "Bad Request", "CONNECT needs a host and a port (host:port).");
        }
        final String host = ipv6 ? null : authority.substring(0, colon);
        final int port;
        try {
            port = Integer.parseInt(authority.substring(colon + 1));
        } catch(NumberFormatException e) {
            throw new HttpError(400, "Bad Request", "Bad port number.");
        }
        if(port < 1 || port > 65535) {
            throw new HttpError(400, "Bad Request", "Bad port number.");
        }

        byte[][] credentials = null;
        for(int i = 1; i < lines.length; i++) {
            final int c = lines[i].indexOf(':');
            if(c <= 0) {
                continue;
            }
            final String name = lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT);
            if(name.equals("proxy-authorization")) {
                credentials = parseBasic(lines[i].substring(c + 1).trim());
            }
        }
        final String profile = ProxyAuthentication.authenticate(config, credentials == null ? null : credentials[1]);
        if(profile == null) {
            throw new HttpError(407, "Proxy Authentication Required", "This proxy needs the password.");
        }
        final String key = (credentials == null) ? null : SocksRequest.makeIsolationKey("socks5", credentials[0], credentials[1]);
        return new Request(host, port, key, profile, ipv6);
    }

    /* User and password of "Basic base64(user:password)", or null for another scheme. */
    private static byte[][] parseBasic(String value) throws HttpError {
        final int sp = value.indexOf(' ');
        if(sp <= 0 || !value.substring(0, sp).equalsIgnoreCase("Basic")) {
            return null;
        }
        final byte[] decoded;
        try {
            decoded = Base64.decode(value.substring(sp + 1).trim());
        } catch(RuntimeException e) {
            throw new HttpError(400, "Bad Request", "Malformed Proxy-Authorization header.");
        }
        int colon = -1;
        for(int i = 0; i < decoded.length; i++) {
            if(decoded[i] == ':') {
                colon = i;
                break;
            }
        }
        if(colon < 0) {
            throw new HttpError(400, "Bad Request", "Malformed Proxy-Authorization header.");
        }
        final byte[] user = new byte[colon];
        final byte[] password = new byte[decoded.length - colon - 1];
        System.arraycopy(decoded, 0, user, 0, user.length);
        System.arraycopy(decoded, colon + 1, password, 0, password.length);
        return new byte[][] { user, password };
    }

    private void sendError(HttpError e) {
        final String body = e.getMessage() + "\r\n";
        final StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.0 ").append(e.status).append(' ').append(e.reason).append("\r\n");
        if(e.status == 407) {
            sb.append("Proxy-Authenticate: Basic realm=\"proxy\"\r\n");
        }
        sb.append("Content-Type: text/plain; charset=us-ascii\r\n");
        sb.append("Content-Length: ").append(body.length()).append("\r\n");
        sb.append("Connection: close\r\n\r\n").append(body);
        try {
            socket.getOutputStream().write(sb.toString().getBytes(LATIN1));
            socket.getOutputStream().flush();
        } catch (IOException ignored) {
            // the client is gone
        }
    }

    private void setReadTimeout(long millis) {
        try {
            socket.setSoTimeout((int) Math.min(millis, Integer.MAX_VALUE));
        } catch (SocketException e) {
            logger.debug("Could not set the HTTP tunnel read timeout: "+ e.getMessage());
        }
    }

    private void closeSocket() {
        try {
            socket.close();
        } catch (IOException e) {
            logger.debug("Error closing HTTP tunnel socket: "+ e.getMessage());
        }
    }
}
