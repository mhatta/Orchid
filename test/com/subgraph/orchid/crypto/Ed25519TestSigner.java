package com.subgraph.orchid.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Test-only Ed25519 <em>signer</em> working directly on a secret scalar, so
 * that tests can produce signatures under blinded keys (a' = h * a mod l)
 * exactly as an onion service does.  Not constant time; never use outside tests.
 */
public final class Ed25519TestSigner {
	public final BigInteger scalar;
	public final byte[] publicKey;

	public Ed25519TestSigner(BigInteger scalar) {
		this.scalar = scalar.mod(Ed25519.L);
		this.publicKey = Ed25519.BASE.multiply(this.scalar).encode();
	}

	public static Ed25519TestSigner random(SecureRandom rng) {
		final byte[] b = new byte[32];
		rng.nextBytes(b);
		return new Ed25519TestSigner(new BigInteger(1, b));
	}

	/** Derive the signer for the blinded key A' = h * A given the clamped blinding factor h. */
	public Ed25519TestSigner blind(byte[] clampedBlindingFactor) {
		final BigInteger h = Ed25519.decodeLittleEndian(clampedBlindingFactor);
		return new Ed25519TestSigner(scalar.multiply(h).mod(Ed25519.L));
	}

	public byte[] sign(byte[] message) {
		return sign(message, "");
	}

	public byte[] sign(byte[] message, String prefix) {
		final byte[] prefixBytes = prefix.getBytes(java.nio.charset.Charset.forName("ISO-8859-1"));
		final byte[] m = new byte[prefixBytes.length + message.length];
		System.arraycopy(prefixBytes, 0, m, 0, prefixBytes.length);
		System.arraycopy(message, 0, m, prefixBytes.length, message.length);

		final MessageDigest sha512 = sha512();
		sha512.update(Ed25519.encodeLittleEndian(scalar));
		sha512.update(m);
		final BigInteger r = Ed25519.decodeLittleEndian(sha512.digest()).mod(Ed25519.L);
		final byte[] rEnc = Ed25519.BASE.multiply(r).encode();
		final MessageDigest h = sha512();
		h.update(rEnc);
		h.update(publicKey);
		h.update(m);
		final BigInteger k = Ed25519.decodeLittleEndian(h.digest()).mod(Ed25519.L);
		final BigInteger s = r.add(k.multiply(scalar)).mod(Ed25519.L);
		final byte[] sig = new byte[64];
		System.arraycopy(rEnc, 0, sig, 0, 32);
		System.arraycopy(Ed25519.encodeLittleEndian(s), 0, sig, 32, 32);
		return sig;
	}

	private static MessageDigest sha512() {
		try {
			return MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
