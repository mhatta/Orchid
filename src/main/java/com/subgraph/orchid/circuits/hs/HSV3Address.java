package com.subgraph.orchid.circuits.hs;

import java.util.Arrays;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.crypto.Ed25519;
import com.subgraph.orchid.data.Base32;

/**
 * A version 3 onion address (rend-spec-v3 section 6 [ONIONADDRESS]):
 * <pre>
 *   onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
 *   CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
 * </pre>
 * where PUBKEY is the 32 byte ed25519 master identity key of the service,
 * VERSION is 0x03 and the base32 encoded part is 56 characters long.
 */
public final class HSV3Address {
	public static final int VERSION = 3;
	public static final int ONION_ADDRESS_LEN = 56;
	private static final int PUBKEY_LEN = 32;
	private static final int CHECKSUM_LEN = 2;
	private static final int DECODED_LEN = PUBKEY_LEN + CHECKSUM_LEN + 1;

	private final byte[] publicKey;
	private final String address;

	private HSV3Address(byte[] publicKey, String address) {
		this.publicKey = publicKey;
		this.address = address;
	}

	/**
	 * Return true if the string looks like (has the length of) a v3 onion address.
	 * The ".onion" suffix is optional.
	 */
	public static boolean isV3AddressLength(String onion) {
		return stripSuffix(onion).length() == ONION_ADDRESS_LEN;
	}

	/**
	 * Parse and validate an onion address.  The ".onion" suffix is optional and
	 * the address is case insensitive.
	 *
	 * @throws TorException if the address is not a valid v3 onion address.
	 */
	public static HSV3Address parse(String onion) {
		final String addr = stripSuffix(onion).toLowerCase();
		if(addr.length() != ONION_ADDRESS_LEN) {
			throw new TorException("Invalid v3 onion address length "+ addr.length() + " (expected "+ ONION_ADDRESS_LEN + ")");
		}
		final byte[] decoded;
		try {
			decoded = Base32.base32Decode(addr);
		} catch (TorException e) {
			throw new TorException("Unable to base32 decode onion address: "+ e.getMessage());
		}
		if(decoded.length != DECODED_LEN) {
			throw new TorException("Decoded onion address has unexpected length "+ decoded.length);
		}
		final int version = decoded[DECODED_LEN - 1] & 0xFF;
		if(version != VERSION) {
			throw new TorException("Unsupported onion address version "+ version);
		}
		final byte[] pubkey = Arrays.copyOfRange(decoded, 0, PUBKEY_LEN);
		final byte[] checksum = Arrays.copyOfRange(decoded, PUBKEY_LEN, PUBKEY_LEN + CHECKSUM_LEN);
		if(!Arrays.equals(checksum, HSV3Crypto.onionChecksum(pubkey, version))) {
			throw new TorException("Onion address has an invalid checksum");
		}
		/*
		 * rend-spec-v3 [CLIENT-VALIDATION]: the client MUST verify that the ed25519
		 * key is a valid point with no torsion component before using it.
		 */
		if(!Ed25519.hasNoTorsionComponent(pubkey)) {
			throw new TorException("Onion address identity key is not a valid torsion-free ed25519 point");
		}
		return new HSV3Address(pubkey, addr);
	}

	/**
	 * Build the onion address string (without the ".onion" suffix) for an ed25519 public key.
	 */
	public static String encode(byte[] publicKey) {
		final byte[] data = new byte[DECODED_LEN];
		System.arraycopy(publicKey, 0, data, 0, PUBKEY_LEN);
		final byte[] checksum = HSV3Crypto.onionChecksum(publicKey, VERSION);
		data[PUBKEY_LEN] = checksum[0];
		data[PUBKEY_LEN + 1] = checksum[1];
		data[DECODED_LEN - 1] = (byte) VERSION;
		return Base32.base32Encode(data);
	}

	private static String stripSuffix(String onion) {
		final String s = onion.trim();
		if(s.toLowerCase().endsWith(".onion")) {
			return s.substring(0, s.length() - 6);
		}
		return s;
	}

	/** The 32 byte ed25519 master identity public key of the service. */
	public byte[] getPublicKey() {
		return publicKey.clone();
	}

	/** The 56 character base32 part of the address (lower case). */
	public String getAddress() {
		return address;
	}

	/** The full address including the ".onion" suffix. */
	public String getOnionAddress() {
		return address + ".onion";
	}

	@Override
	public boolean equals(Object o) {
		return (o instanceof HSV3Address) && Arrays.equals(((HSV3Address) o).publicKey, publicKey);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(publicKey);
	}

	@Override
	public String toString() {
		return getOnionAddress();
	}
}
