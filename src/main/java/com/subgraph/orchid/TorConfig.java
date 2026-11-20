package com.subgraph.orchid;

import java.io.File;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.config.TorConfigBridgeLine;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;


public interface TorConfig {
	
	/**
	 * The directory where Orchid keeps its state (entry guards) and its
	 * directory caches.  It must be writable: TorClient#start() fails
	 * otherwise.  The default is ~/.orchid, except on Android, where there
	 * is no default and the application must set one, preferably under
	 * Context#getNoBackupFilesDir() so that it stays out of backups.
	 */
	File getDataDirectory();
	void setDataDirectory(File directory);
	
	long getCircuitBuildTimeout();
	void setCircuitBuildTimeout(long time, TimeUnit unit);
	
	long getCircuitStreamTimeout();
	void setCircuitStreamTimeout(long time, TimeUnit unit);
	
	long getCircuitIdleTimeout();
	void setCircuitIdleTimeout(long time, TimeUnit unit);
	
	long getNewCircuitPeriod();
	void setNewCircuitPeriod(long time, TimeUnit unit);
	
	long getMaxCircuitDirtiness();
	void setMaxCircuitDirtiness(long time, TimeUnit unit);
	
	int getMaxClientCircuitsPending();
	void setMaxClientCircuitsPending(int value);
	
	boolean getEnforceDistinctSubnets();
	void setEnforceDistinctSubnets(boolean value);
	
	long getSocksTimeout();
	void setSocksTimeout(long value);
	
	/**
	 * Unused since 2.6.0: the number of primary guards comes from the
	 * consensus (guard-n-primary-guards), as in guard-spec.
	 */
	@Deprecated
	int getNumEntryGuards();
	/** Unused since 2.6.0; see {@link #getNumEntryGuards()}. */
	@Deprecated
	void setNumEntryGuards(int value);
	
	boolean getUseEntryGuards();
	void setUseEntryGuards(boolean value);
	
	List<Integer> getLongLivedPorts();
	void setLongLivedPorts(List<Integer> ports);

	List<String> getExcludeNodes();
	void setExcludeNodes(List<String> nodes);
	
	List<String> getExcludeExitNodes();
	
	void setExcludeExitNodes(List<String> nodes);
	
	List<String> getExitNodes();
	void setExitNodes(List<String> nodes);
	
	List<String> getEntryNodes();
	void setEntryNodes(List<String> nodes);
	
	boolean getStrictNodes();
	void setStrictNodes(boolean value);
	
	boolean getFascistFirewall();
	void setFascistFirewall(boolean value);
	
	List<Integer> getFirewallPorts();
	void setFirewallPorts(List<Integer> ports);
	
	boolean getSafeSocks();
	void setSafeSocks(boolean value);

	/**
	 * The local address the SOCKS listener binds to.  The default is the
	 * loopback address 127.0.0.1, so that only programs on this computer can
	 * use the proxy.  Set it to another address (for example 0.0.0.0) only
	 * if other machines are meant to reach it, and protect that address
	 * with a firewall.
	 */
	String getSocksListenAddress();
	void setSocksListenAddress(String address);

	/**
	 * The password that SOCKS clients must give (SOCKS 5 username/password
	 * authentication, RFC 1929), or null (the default) to accept clients
	 * without authentication.  With a password, SOCKS 4 is refused.  The
	 * user name is free, and streams with different user names never share
	 * a circuit.
	 *
	 * On Android every app can connect to a SOCKS port on 127.0.0.1; a
	 * random password, given only to the app's own HTTP client, keeps the
	 * other apps out.
	 *
	 * The default implementation returns null.
	 */
	default String getSocksPassword() {
		return null;
	}

	/** See {@link #getSocksPassword()}.  The default implementation throws UnsupportedOperationException. */
	default void setSocksPassword(String password) {
		throw new UnsupportedOperationException("setSocksPassword");
	}

	/**
	 * Whether streams from the SOCKS and HTTP tunnel ports to different
	 * destination hosts never share a circuit (Tor's IsolateDestAddr).  Off
	 * by default.
	 *
	 * Turn it on when the clients cannot send credentials to isolate their
	 * streams themselves: the Wi-Fi proxy setting of Android, and many apps,
	 * send none, so that without it all their streams share the same exit
	 * circuits, for up to MaxCircuitDirtiness (ten minutes).  The host is
	 * added to whatever isolation the credentials give.  Each host then
	 * needs a circuit of its own: more circuits are built, and the first
	 * connection to a host waits for one.  Up to
	 * {@code CircuitManagerImpl.MAX_ISOLATION_GROUPS} groups are open at
	 * once; when they are all in use, the idle circuit of the group used
	 * longest ago is closed to make room.
	 *
	 * It isolates by host name (or address) as the client sends it, not by
	 * site: www.example.com and static.example.com get different circuits,
	 * and a third party embedded in two sites shares a circuit between
	 * them.  It does not apply to {@code TorClient#getSocketFactory} or
	 * {@code TorClient#openExitStreamTo}, which take an isolation key.
	 *
	 * The default implementation returns false.
	 *
	 * @since 2.8.0
	 */
	default boolean getIsolateDestAddr() {
		return false;
	}

	/** See {@link #getIsolateDestAddr()}.  The default implementation throws UnsupportedOperationException. */
	default void setIsolateDestAddr(boolean value) {
		throw new UnsupportedOperationException("setIsolateDestAddr");
	}
	
	/**
	 * Whether log messages leave out the destinations of streams (the host
	 * names, addresses and onion addresses that SOCKS clients connect to).
	 * On by default.  As the logger, this applies to the whole process.
	 */
	boolean getSafeLogging();
	void setSafeLogging(boolean value);

	boolean getWarnUnsafeSocks();
	void setWarnUnsafeSocks(boolean value);

	boolean getClientRejectInternalAddress();
	void setClientRejectInternalAddress(boolean value);
	
	/**
	 * @deprecated Ignored.  Orchid always uses the in-protocol (v3) link
	 * handshake, which every relay supports.
	 */
	@Deprecated
	boolean getHandshakeV3Enabled();
	/** @deprecated Ignored; see {@link #getHandshakeV3Enabled()}. */
	@Deprecated
	void setHandshakeV3Enabled(boolean value);

	/**
	 * @deprecated Ignored.  The renegotiation based v2 link handshake is
	 * no longer supported by relays, and Orchid no longer implements it.
	 */
	@Deprecated
	boolean getHandshakeV2Enabled();
	/** @deprecated Ignored; see {@link #getHandshakeV2Enabled()}. */
	@Deprecated
	void setHandshakeV2Enabled(boolean value);
	
	/**
	 * Return the x25519 private key configured for client authorization
	 * (restricted discovery) with the given v3 onion service, or null.
	 */
	byte[] getOnionClientAuthKey(String onionAddress);

	/**
	 * Configure a client authorization key for a v3 onion service.
	 *
	 * @param onionAddress The onion address (with or without ".onion").
	 * @param base32PrivateKey The base32 encoded x25519 private key, as in
	 *        a ClientOnionAuthDir file ("&lt;onion&gt;:descriptor:x25519:&lt;key&gt;").
	 */
	void addOnionClientAuth(String onionAddress, String base32PrivateKey);
	
	/**
	 * @deprecated Ignored.  Every circuit hop is created with the ntor
	 * handshake; the TAP handshake is no longer accepted by relays.
	 */
	@Deprecated
	AutoBoolValue getUseNTorHandshake();
	/** @deprecated Ignored; see {@link #getUseNTorHandshake()}. */
	@Deprecated
	void setUseNTorHandshake(AutoBoolValue value);
	
	AutoBoolValue getUseMicrodescriptors();
	void setUseMicrodescriptors(AutoBoolValue value);

	boolean getUseBridges();
	void setUseBridges(boolean value);
	
	List<TorConfigBridgeLine> getBridges();
	void addBridge(IPv4Address address, int port);
	void addBridge(IPv4Address address, int port, HexDigest fingerprint);
	
	enum AutoBoolValue { TRUE, FALSE, AUTO }
}