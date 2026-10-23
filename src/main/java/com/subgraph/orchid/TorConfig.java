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
	
	int getNumEntryGuards();
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