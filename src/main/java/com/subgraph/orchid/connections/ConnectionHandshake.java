package com.subgraph.orchid.connections;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLSocket;

import com.subgraph.orchid.BridgeRouter;
import com.subgraph.orchid.Cell;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionIOException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.Logger;

public abstract class ConnectionHandshake {
    private static final Logger logger = Logger.getInstance(ConnectionHandshake.class);
	
    /**
     * The link protocol versions Orchid offers in its VERSIONS cell.
     *
     * Version 4 widens circuit ids to 4 bytes and version 5 adds link
     * padding (which Orchid receives and ignores, and does not negotiate).
     * Every relay on the network supports both; version 3 and the older
     * renegotiation based handshakes are not offered any more.
     */
    static final int[] SUPPORTED_LINK_VERSIONS = { 4, 5 };

    static ConnectionHandshake createHandshake(TorConfig config, ConnectionImpl connection, SSLSocket socket) throws ConnectionHandshakeException {
        if(ConnectionHandshakeV3.sessionSupportsHandshake(socket.getSession())) {
            return new ConnectionHandshakeV3(connection, socket);
        } else {
            throw new ConnectionHandshakeException("Relay does not support the in-protocol (v3) link handshake");
        }
    }

    /**
     * Return the versions listed in a VERSIONS cell, without changing the
     * cell's read position.
     */
    static List<Integer> readVersions(Cell versionsCell) {
        final List<Integer> versions = new ArrayList<Integer>();
        final int end = versionsCell.getCellBytes().length - 1;
        for(int i = Cell.CELL_VAR_HEADER_LEN; i < end; i += 2) {
            versions.add(versionsCell.getShortAt(i));
        }
        return versions;
    }

    /**
     * Return the highest link protocol version that both Orchid and the
     * relay support, or 0 if there is none.
     */
    static int chooseLinkProtocolVersion(List<Integer> remoteVersions) {
        int best = 0;
        for(int v: SUPPORTED_LINK_VERSIONS) {
            if(v > best && remoteVersions.contains(v)) {
                best = v;
            }
        }
        return best;
    }

    protected final ConnectionImpl connection;
    protected final SSLSocket socket;

    protected final List<Integer> remoteVersions;
    private int remoteTimestamp;
    private IPv4Address myAddress;
    private final List<IPv4Address> remoteAddresses;

    ConnectionHandshake(ConnectionImpl connection, SSLSocket socket) {
        this.connection = connection;
        this.socket = socket;
        this.remoteVersions = new ArrayList<Integer>();
        this.remoteAddresses = new ArrayList<IPv4Address>();
    }

    abstract void runHandshake() throws IOException, InterruptedException, ConnectionIOException;

    int getRemoteTimestamp() {
        return remoteTimestamp;
    }

    IPv4Address getMyAddress() {
        return myAddress;
    }

    protected Cell expectCell(Integer... expectedTypes) throws ConnectionHandshakeException {
        try {
            final Cell c = connection.readConnectionControlCell();
            for(int t: expectedTypes) {
                if(c.getCommand() == t) {
                    return c;
                }
            }
            final List<Integer> expected = Arrays.asList(expectedTypes);
            throw new ConnectionHandshakeException("Expecting Cell command "+ expected + " and got [ "+ c.getCommand() +" ] instead");
        } catch (ConnectionIOException e) {
            throw new ConnectionHandshakeException("Connection exception while performing handshake "+ e);
        }
    }

    protected  void sendVersions(int... versions) throws ConnectionIOException {
        final Cell cell = CellImpl.createVarCell(0, Cell.VERSIONS, versions.length * 2);
        for(int v: versions) {
            cell.putShort(v);
        }
        connection.sendCell(cell);
    }

    protected void receiveVersions() throws ConnectionHandshakeException {
        final Cell c = expectCell(Cell.VERSIONS);
        remoteVersions.addAll(readVersions(c));
        if(connection.getLinkProtocolVersion() == 0) {
            throw new ConnectionHandshakeException("No common link protocol version, relay offers "+ remoteVersions);
        }
    }

    protected void sendNetinfo() throws ConnectionIOException {
        final Cell cell = CellImpl.createCell(0, Cell.NETINFO);
        putTimestamp(cell);
        putIPv4Address(cell, connection.getRouter().getAddress());
        putMyAddresses(cell);
        connection.sendCell(cell);
    }

    private void putTimestamp(Cell cell) {
        final Date now = new Date();
        cell.putInt((int) (now.getTime() / 1000));
    }

    private void putIPv4Address(Cell cell, IPv4Address address) {
        final byte[] data = address.getAddressDataBytes();
        cell.putByte(Cell.ADDRESS_TYPE_IPV4);
        cell.putByte(data.length); 
        cell.putByteArray(data);
    }

    private void putMyAddresses(Cell cell) {
        cell.putByte(1);
        putIPv4Address(cell, new IPv4Address(0));
    }

    protected void recvNetinfo() throws ConnectionHandshakeException {
        processNetInfo(expectCell(Cell.NETINFO));
    }

    protected void processNetInfo(Cell netinfoCell) {
        remoteTimestamp = netinfoCell.getInt();
        myAddress = readAddress(netinfoCell);
        final int addressCount = netinfoCell.getByte();
        for(int i = 0; i < addressCount; i++) {
            IPv4Address addr = readAddress(netinfoCell);
            if(addr != null) {
                remoteAddresses.add(addr);
            }
        }
    }

    private IPv4Address readAddress(Cell cell) {
        final int type = cell.getByte();
        final int len = cell.getByte();
        if(type == Cell.ADDRESS_TYPE_IPV4 && len == 4) {
            return new IPv4Address(cell.getInt());
        }
        final byte[] buffer = new byte[len];
        cell.getByteArray(buffer);
        return null;
    }

    protected void verifyIdentityKey(PublicKey publicKey) throws ConnectionHandshakeException {
        if(!(publicKey instanceof RSAPublicKey)) {
            throw new ConnectionHandshakeException("Identity certificate public key is not an RSA key as expected");
        }
        final TorPublicKey identityKey = new TorPublicKey((RSAPublicKey)publicKey);
        final Router router = connection.getRouter();
        if((router instanceof BridgeRouter) && (router.getIdentityHash() == null)) {
            logger.info("Setting Bridge fingerprint from connection handshake for "+ router);
            ((BridgeRouter) router).setIdentity(identityKey.getFingerprint());
        } else if(!identityKey.getFingerprint().equals(router.getIdentityHash())) {
            throw new ConnectionHandshakeException("Router identity does not match certificate key");
        }
    }
}
