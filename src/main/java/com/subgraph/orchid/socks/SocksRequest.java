package com.subgraph.orchid.socks;

import java.io.IOException;
import java.net.Socket;
import java.security.MessageDigest;

import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.Logger;

public abstract class SocksRequest {
    private static final Logger logger = Logger.getInstance(SocksRequest.class);

    /*
     * Upper bound on the NUL terminated strings of a SOCKS 4/4a request
     * (user id, hostname), so that a client cannot make Orchid buffer an
     * endless string.  A hostname is at most 255 bytes.
     */
    static final int MAX_STRING_LENGTH = 255;
	
    private final TorConfig config;
    private final Socket socket;

    private byte[] addressData;
    private IPv4Address address;
    private String hostname;
    private int port;

    private long lastWarningTimestamp = 0;

    /* See getIsolationKey(). */
    private String isolationKey;

    protected SocksRequest(TorConfig config, Socket socket) {
        this.config = config;
        this.socket = socket;
    }

    abstract public void readRequest() throws SocksRequestException;
    abstract public int getCommandCode();
    abstract public boolean isConnectRequest();
    abstract void sendError(boolean isUnsupportedCommand) throws SocksRequestException;
    abstract void sendSuccess() throws SocksRequestException;
    abstract void sendConnectionRefused() throws SocksRequestException;

    /**
     * The stream isolation key of this request: streams with different
     * keys never share a circuit (Tor's IsolateSOCKSAuth, on by default).
     * It is made from the SOCKS 5 user name and password, or the SOCKS 4
     * user id, and is null when the client sent none.
     */
    public String getIsolationKey() {
        return isolationKey;
    }

    /*
     * The parts are hex encoded, and the encodings cannot contain ':', so
     * that user "a:b" with password "c" and user "a" with password "b:c"
     * give different keys.  (java.util.Base64 needs Android API level 26.)
     */
    protected void setIsolationKey(String kind, byte[]... parts) {
        final StringBuilder sb = new StringBuilder(kind);
        for(byte[] part: parts) {
            sb.append(':');
            for(byte b: part) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
        }
        isolationKey = sb.toString();
    }

    protected TorConfig getConfig() {
        return config;
    }

    /* Compares without leaking, through the time taken, how much of a matched. */
    protected static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    public int getPort() {
        return port;
    }

    public IPv4Address getAddress() {
        return address;
    }

    public boolean hasHostname() {
        return hostname != null;
    }

    public String getHostname() {
        return hostname;
    }

    public String getTarget() {
        if(config.getSafeLogging()) {
            return "[scrubbed]:"+ port;
        }
        if(hostname != null) {
            return hostname + ":" + port;
        } else {
            return address + ":" + port;
        }
    }

    protected void setPortData(byte[] data) throws SocksRequestException {
        if(data.length != 2){
            throw new SocksRequestException();
        }
        port = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
    }

    protected void setIPv4AddressData(byte[] data) throws SocksRequestException {
        logUnsafeSOCKS();

        if(data.length != 4)
            throw new SocksRequestException();
        addressData = data;

        int addressValue = 0;
        for(byte b: addressData) {
            addressValue <<= 8;
            addressValue |= (b & 0xFF);
        }
        address = new IPv4Address(addressValue);
    }

    private boolean testRateLimit() {
        final long now = System.currentTimeMillis();
        final long diff = now - lastWarningTimestamp;
        lastWarningTimestamp = now;
        return diff > 5000;
    }

    private void logUnsafeSOCKS() throws SocksRequestException {
        if((config.getWarnUnsafeSocks() || config.getSafeSocks()) && testRateLimit()) {
            logger.warn("Your application is giving Orchid only "+
                                            "an IP address.  Applications that do DNS "+
                                            "resolves themselves may leak information. "+
                                            "Consider using Socks4a (e.g. via privoxy or socat) "+ 
                                            "instead.  For more information please see "+
                                            "https://wiki.torproject.org/TheOnionRouter/TorFAQ#SOCKSAndDNS");
        }
        if(config.getSafeSocks()) {
            throw new SocksRequestException("Rejecting unsafe SOCKS request");
        }		
    }

    protected void setHostname(String name) {
        hostname = name;
    }

    protected byte[] readPortData() throws SocksRequestException {
        final byte[] data = new byte[2];
        readAll(data, 0, 2);
        return data;
    }

    protected byte[] readIPv4AddressData() throws SocksRequestException {
        final byte[] data = new byte[4];
        readAll(data);
        return data;
    }

    protected byte[] readIPv6AddressData() throws SocksRequestException {
        final byte[] data = new byte[16];
        readAll(data);
        return data;
    }

    protected String readNullTerminatedString() throws SocksRequestException {
        try {
            final StringBuilder sb = new StringBuilder();
            while(true) {
                final int c = socket.getInputStream().read();
                if(c == -1){
                    throw new SocksRequestException();
                }
                if(c == 0){
                    return sb.toString();
                }
                if(sb.length() >= MAX_STRING_LENGTH) {
                    throw new SocksRequestException("SOCKS request string longer than "+ MAX_STRING_LENGTH +" bytes");
                }
                char ch = (char) c;
                sb.append(ch);
            }
        } catch (IOException e) {
            throw new SocksRequestException(e);
        }
    }

    protected int readByte() throws SocksRequestException {
        try {
            final int n = socket.getInputStream().read();
            if(n == -1){
                throw new SocksRequestException();
            }
            return n;
        } catch (IOException e) {
            throw new SocksRequestException(e);
        }
    }

    protected void readAll(byte[] buffer) throws SocksRequestException {
        readAll(buffer, 0, buffer.length);
    }

    protected void readAll(byte[] buffer, int offset, int length) throws SocksRequestException {
        try {
            while(length > 0) {
                int n = socket.getInputStream().read(buffer, offset, length);
                if(n == -1){
                    throw new SocksRequestException();
                }
                offset += n;
                length -= n;
            }
        } catch (IOException e) {
            throw new SocksRequestException(e);
        }
    }

    protected void socketWrite(byte[] buffer) throws SocksRequestException {
        try {
            socket.getOutputStream().write(buffer);
        } catch(IOException e) {
            throw new SocksRequestException(e);
        }
    }
}
