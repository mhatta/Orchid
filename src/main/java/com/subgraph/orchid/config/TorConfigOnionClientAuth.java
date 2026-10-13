package com.subgraph.orchid.config;

import java.util.HashMap;
import java.util.Map;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.hs.HSV3Address;
import com.subgraph.orchid.data.Base32;

/**
 * Storage for version 3 onion service client authorization keys (restricted
 * discovery, rend-spec-v3 section 2.5.1.2 / appendix G).  Each entry maps an
 * onion address to the client's x25519 private key, in the same base32
 * encoding used by C Tor's <code>ClientOnionAuthDir</code> files:
 * <pre>
 *   &lt;onion-address&gt;:descriptor:x25519:&lt;base32-encoded-private-key&gt;
 * </pre>
 */
public class TorConfigOnionClientAuth {
	private static final int X25519_KEY_LEN = 32;

	private final Map<String, byte[]> keys = new HashMap<String, byte[]>();

	/**
	 * @param onionAddress The v3 onion address (with or without ".onion").
	 * @param base32PrivateKey The 52 character base32 encoded x25519 private key.
	 */
	void add(String onionAddress, String base32PrivateKey) {
		final String key = normalizeAddress(onionAddress);
		final byte[] decoded;
		try {
			decoded = Base32.base32Decode(base32PrivateKey.trim());
		} catch (TorException e) {
			throw new IllegalArgumentException("Invalid base32 client authorization key: "+ e.getMessage());
		}
		if(decoded.length != X25519_KEY_LEN) {
			throw new IllegalArgumentException("Client authorization key must decode to "+ X25519_KEY_LEN + " bytes");
		}
		keys.put(key, decoded);
	}

	/**
	 * Add an entry from a line in the ClientOnionAuthDir file format
	 * ("address:descriptor:x25519:key").
	 */
	void addLine(String line) {
		final String[] parts = line.trim().split(":");
		if(parts.length != 4 || !"descriptor".equals(parts[1]) || !"x25519".equals(parts[2])) {
			throw new IllegalArgumentException("Client authorization entry must have the form <onion>:descriptor:x25519:<key>");
		}
		add(parts[0], parts[3]);
	}

	byte[] get(String onionAddress) {
		final byte[] key = keys.get(normalizeAddress(onionAddress));
		return key == null ? null : key.clone();
	}

	private static String normalizeAddress(String onionAddress) {
		try {
			return HSV3Address.parse(onionAddress).getAddress();
		} catch (TorException e) {
			throw new IllegalArgumentException("Invalid v3 onion address: "+ e.getMessage());
		}
	}
}
