package com.subgraph.orchid;

import java.io.File;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
	
	/**
	 * How long a circuit built in advance may stay open without ever
	 * carrying a stream, in milliseconds (Tor's former CircuitIdleTimeout,
	 * now CircuitsAvailableTimeout).  Each such circuit is closed after a
	 * random time between half of it and all of it, so that they do not all
	 * close at once; if its port is still predicted, a fresh one is built.
	 * One hour by default: unused circuits close after 30 to 60 minutes, and
	 * then the connection to the guard can close too.  Before 2.8.0 the
	 * option was ignored, and unused circuits stayed open for ever.
	 */
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
	
	/**
	 * Whether the SOCKS and HTTP tunnel ports refuse requests that give an
	 * IP address instead of a host name (Tor's SafeSocks): SOCKS 4 (not
	 * 4a), SOCKS 5 with an IPv4 or IPv6 address, and, unlike Tor, a host
	 * name or a CONNECT authority that is an address literal.  An
	 * application that sends one has most likely looked the name up itself,
	 * through the device's DNS resolver and outside Tor.  Off by default;
	 * the refused requests are counted (see
	 * {@link TorClient#getProxyStatistics()}).  Read for each request, so
	 * it can be changed while the client runs.
	 */
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
	 * other apps out.  To give each application its own password, use
	 * {@link #setSocksPasswords(Map)}; a client may then give either.
	 *
	 * The password is read for each request, so it can be changed while
	 * the client runs; streams already open are not affected.
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
	 * Password profiles: a password for each named application (or group of
	 * them), any of which the SOCKS and HTTP tunnel ports accept, with any
	 * user name.  Unmodifiable; empty (the default) for none.  When there
	 * is at least one, clients must give a password, as with
	 * {@link #getSocksPassword()} (which they may give instead), and
	 * SOCKS 4 is refused.
	 *
	 * Streams with different credentials never share a circuit, so each
	 * profile gets its own circuits: an app cannot ride on the circuits of
	 * another, or learn from their timing which hosts it went to.  The
	 * requests are counted by profile (see
	 * {@link TorClient#getProxyStatistics()}), which says, for instance,
	 * which app gives addresses instead of host names.
	 *
	 * The profiles are read for each request, so they can be changed while
	 * the client runs; streams already open are not affected.
	 *
	 * The default implementation returns an empty map.
	 *
	 * @since 2.9.0
	 */
	default Map<String, String> getSocksPasswords() {
		return Collections.emptyMap();
	}

	/**
	 * See {@link #getSocksPasswords()}: profile name to password, copied;
	 * null or an empty map for none.  The names and passwords must not be
	 * null or empty, a password must be at most 255 bytes in UTF-8 (the
	 * most SOCKS 5 can carry), and no two profiles may have the same
	 * password, or IllegalArgumentException is thrown.  The default
	 * implementation throws UnsupportedOperationException.
	 *
	 * @since 2.9.0
	 */
	default void setSocksPasswords(Map<String, String> passwordsByProfile) {
		throw new UnsupportedOperationException("setSocksPasswords");
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

	/** Tor's default DormantClientTimeout: 24 hours. */
	long DEFAULT_DORMANT_CLIENT_TIMEOUT = 24L * 60 * 60 * 1000;

	/** Tor's lowest DormantClientTimeout: 10 minutes. */
	long MIN_DORMANT_CLIENT_TIMEOUT = 10L * 60 * 1000;

	/**
	 * After how many milliseconds without client activity Orchid becomes
	 * dormant (Tor's DormantClientTimeout): it stops building circuits in
	 * advance and downloading directory information, closes the circuits
	 * that no stream uses, and asks its guards to stop padding, so that the
	 * device's radio and CPU can rest.  A new stream request wakes it up.
	 * Client activity is a stream request from an application and, with
	 * {@link #getDormantTimeoutDisabledByIdleStreams()}, any open stream.
	 * 24 hours by default; at least 10 minutes.  An Android app may choose
	 * 30 minutes or an hour.  See {@code TorClient#setDormant(boolean)}.
	 *
	 * The default implementation returns {@link #DEFAULT_DORMANT_CLIENT_TIMEOUT}.
	 *
	 * @since 2.8.0
	 */
	default long getDormantClientTimeout() {
		return DEFAULT_DORMANT_CLIENT_TIMEOUT;
	}

	/**
	 * See {@link #getDormantClientTimeout()}, which returns milliseconds;
	 * for example <code>setDormantClientTimeout(30, TimeUnit.MINUTES)</code>.
	 *
	 * @throws IllegalArgumentException if it is less than {@link #MIN_DORMANT_CLIENT_TIMEOUT}.
	 *         The default implementation throws UnsupportedOperationException.
	 */
	default void setDormantClientTimeout(long time, TimeUnit unit) {
		throw new UnsupportedOperationException("setDormantClientTimeout");
	}

	/**
	 * Whether Orchid becomes dormant by itself after
	 * {@link #getDormantClientTimeout()} without client activity (Tor's
	 * DormantTimeoutEnabled).  On by default.  When off, it is dormant only
	 * when the application says so.  The default implementation returns true.
	 *
	 * @since 2.8.0
	 */
	default boolean getDormantTimeoutEnabled() {
		return true;
	}

	/** See {@link #getDormantTimeoutEnabled()}.  The default implementation throws UnsupportedOperationException. */
	default void setDormantTimeoutEnabled(boolean value) {
		throw new UnsupportedOperationException("setDormantTimeoutEnabled");
	}

	/**
	 * Whether an open stream, even one that sends and receives nothing,
	 * counts as client activity and keeps Orchid from becoming dormant
	 * (Tor's DormantTimeoutDisabledByIdleStreams).  On by default.  Turn it
	 * off when applications keep connections open that matter little, such
	 * as an idle HTTP keep-alive connection.  The default implementation
	 * returns true.
	 *
	 * @since 2.8.0
	 */
	default boolean getDormantTimeoutDisabledByIdleStreams() {
		return true;
	}

	/** See {@link #getDormantTimeoutDisabledByIdleStreams()}.  The default implementation throws UnsupportedOperationException. */
	default void setDormantTimeoutDisabledByIdleStreams(boolean value) {
		throw new UnsupportedOperationException("setDormantTimeoutDisabledByIdleStreams");
	}

	/**
	 * Whether entry guards may send padding cells on Orchid's connections
	 * to them (Tor's ConnectionPadding).  On by default.  Guards send one
	 * on a quiet connection every 1.5 to 9.5 seconds, to blur the records
	 * that ISPs keep of connections; each one can wake a mobile device's
	 * radio.  When off, Orchid asks each guard not to (a PADDING_NEGOTIATE
	 * STOP cell, link protocol 5).  Orchid itself sends no padding.
	 * Whatever this says, Orchid asks for no padding while it is dormant.
	 * The default implementation returns true.
	 *
	 * @since 2.8.0
	 */
	default boolean getConnectionPadding() {
		return true;
	}

	/** See {@link #getConnectionPadding()}.  The default implementation throws UnsupportedOperationException. */
	default void setConnectionPadding(boolean value) {
		throw new UnsupportedOperationException("setConnectionPadding");
	}
	
	/**
	 * Whether log messages leave out the destinations of streams (the host
	 * names, addresses and onion addresses that SOCKS clients connect to),
	 * and, since 2.9.0, the addresses of relays and bridges and the IP
	 * addresses in socket errors: relays are named by nickname only and
	 * bridges as "[Bridge]".  On by default.  As the logger, this applies
	 * to the whole process.  {@link com.subgraph.orchid.Router#getNickname()}
	 * of a bridge still gives its address, for showing to the user.
	 */
	boolean getSafeLogging();
	void setSafeLogging(boolean value);

	/**
	 * Whether to log a warning (at most every five seconds) when a request
	 * gives an IP address instead of a host name: see
	 * {@link #getSafeSocks()}.  On by default, as in Tor.
	 */
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