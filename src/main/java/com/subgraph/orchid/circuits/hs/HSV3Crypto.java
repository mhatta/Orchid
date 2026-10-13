package com.subgraph.orchid.circuits.hs;

import java.nio.charset.Charset;

import com.subgraph.orchid.crypto.Ed25519;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.crypto.Keccak;

/**
 * The key derivations of the version 3 onion service protocol that do not
 * belong to the hs-ntor handshake itself (rend-spec-v3 sections 2.1, 2.2 and
 * appendix A [KEYBLIND]).  All hashes are SHA3-256 and INT_8 denotes an 8 byte
 * big endian integer.
 */
public final class HSV3Crypto {
	private static final Charset ASCII = Charset.forName("ISO-8859-1");

	/** Blinding string: "Derive temporary signing key" | INT_1(0) */
	static final byte[] BLIND_STRING = concat("Derive temporary signing key".getBytes(ASCII), new byte[] { 0 });
	/** The ed25519 base point B, as the literal string used by the C Tor implementation. */
	static final byte[] ED25519_BASEPOINT_STRING = (
			"(15112221349535400772501151409588531511454012693041857206046113283949847762202, " +
			"46316835694926478169428394003475163141307993866256225615783033603165251855960)").getBytes(ASCII);
	static final byte[] KEYBLIND_NONCE_PREFIX = "key-blind".getBytes(ASCII);
	static final byte[] CREDENTIAL_PREFIX = "credential".getBytes(ASCII);
	static final byte[] SUBCREDENTIAL_PREFIX = "subcredential".getBytes(ASCII);
	static final byte[] ONION_CHECKSUM_PREFIX = ".onion checksum".getBytes(ASCII);
	static final byte[] DISASTER_SRV_PREFIX = "shared-random-disaster".getBytes(ASCII);
	static final byte[] HS_INDEX_PREFIX = "store-at-idx".getBytes(ASCII);
	static final byte[] HSDIR_INDEX_PREFIX = "node-idx".getBytes(ASCII);

	private HSV3Crypto() {}

	/**
	 * CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
	 */
	public static byte[] onionChecksum(byte[] identityPublicKey, int version) {
		final byte[] digest = Keccak.digestSha3_256(ONION_CHECKSUM_PREFIX, identityPublicKey, new byte[] { (byte) version });
		return new byte[] { digest[0], digest[1] };
	}

	/**
	 * N_hs_cred = H("credential" | public-identity-key)
	 */
	public static byte[] credential(byte[] identityPublicKey) {
		return Keccak.digestSha3_256(CREDENTIAL_PREFIX, identityPublicKey);
	}

	/**
	 * N_hs_subcred = H("subcredential" | N_hs_cred | blinded-public-key)
	 */
	public static byte[] subcredential(byte[] identityPublicKey, byte[] blindedPublicKey) {
		return Keccak.digestSha3_256(SUBCREDENTIAL_PREFIX, credential(identityPublicKey), blindedPublicKey);
	}

	/**
	 * The nonce N = "key-blind" | INT_8(period-number) | INT_8(period_length)
	 */
	public static byte[] keyBlindNonce(long periodNumber, long periodLength) {
		return concat(KEYBLIND_NONCE_PREFIX, HSNtorKeyAgreement.int8(periodNumber), HSNtorKeyAgreement.int8(periodLength));
	}

	/**
	 * The (unclamped) blinding parameter h = H(BLIND_STRING | A | s | B | N)
	 * where the optional secret s is empty for clients.
	 */
	public static byte[] blindingParameter(byte[] identityPublicKey, long periodNumber, long periodLength) {
		return Keccak.digestSha3_256(BLIND_STRING, identityPublicKey, ED25519_BASEPOINT_STRING, keyBlindNonce(periodNumber, periodLength));
	}

	/**
	 * The blinded public key A' = h * A for the given time period.
	 */
	public static byte[] blindedPublicKey(byte[] identityPublicKey, long periodNumber, long periodLength) {
		final byte[] h = Ed25519.clampScalar(blindingParameter(identityPublicKey, periodNumber, periodLength));
		return Ed25519.blindPublicKey(identityPublicKey, h);
	}

	/**
	 * Disaster shared random value, used when the consensus lacks the needed
	 * SRV:  SRV = H("shared-random-disaster" | INT_8(period_length) | INT_8(period_num))
	 */
	public static byte[] disasterSharedRandomValue(long periodLength, long periodNumber) {
		return Keccak.digestSha3_256(DISASTER_SRV_PREFIX, HSNtorKeyAgreement.int8(periodLength), HSNtorKeyAgreement.int8(periodNumber));
	}

	/**
	 * hs_index(replicanum) = H("store-at-idx" | blinded_public_key | INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))
	 */
	public static byte[] hsIndex(int replica, byte[] blindedPublicKey, long periodLength, long periodNumber) {
		return Keccak.digestSha3_256(HS_INDEX_PREFIX, blindedPublicKey,
				HSNtorKeyAgreement.int8(replica), HSNtorKeyAgreement.int8(periodLength), HSNtorKeyAgreement.int8(periodNumber));
	}

	/**
	 * hsdir_index(node) = H("node-idx" | node_identity | shared_random_value | INT_8(period_num) | INT_8(period_length))
	 */
	public static byte[] hsdirIndex(byte[] nodeEd25519Identity, byte[] sharedRandomValue, long periodNumber, long periodLength) {
		return Keccak.digestSha3_256(HSDIR_INDEX_PREFIX, nodeEd25519Identity, sharedRandomValue,
				HSNtorKeyAgreement.int8(periodNumber), HSNtorKeyAgreement.int8(periodLength));
	}

	static byte[] concat(byte[]... parts) {
		return HSNtorKeyAgreement.concat(parts);
	}
}
