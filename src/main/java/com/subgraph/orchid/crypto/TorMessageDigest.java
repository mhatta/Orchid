package com.subgraph.orchid.crypto;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.data.HexDigest;

/**
 * This class wraps the cryptographic message digest algorithms used in Tor:
 * SHA-1 (the historical default), SHA-256, and SHA3-256 (used by the v3 onion
 * service protocol for the rendezvous circuit hop).
 */
public class TorMessageDigest {

	public enum Algorithm { SHA1, SHA256, SHA3_256 }

	public static final int TOR_DIGEST_SIZE = 20;
	public static final int TOR_DIGEST256_SIZE = 32;

	private static final String TOR_DIGEST_ALGORITHM = "SHA-1";
	private static final String TOR_DIGEST256_ALGORITHM = "SHA-256";

	/* Exactly one of these is non-null */
	private final MessageDigest digestInstance;
	private final Keccak keccakInstance;
	private final Algorithm algorithm;

	public TorMessageDigest(boolean isDigest256) {
		this(isDigest256 ? Algorithm.SHA256 : Algorithm.SHA1);
	}

	public TorMessageDigest() {
		this(false);
	}

	public TorMessageDigest(Algorithm algorithm) {
		this.algorithm = algorithm;
		if(algorithm == Algorithm.SHA3_256) {
			this.keccakInstance = Keccak.sha3_256();
			this.digestInstance = null;
		} else {
			this.keccakInstance = null;
			this.digestInstance = createDigestInstance(algorithm == Algorithm.SHA256);
		}
	}

	/** Create a SHA3-256 digest instance (pure Java, no JCA provider required). */
	public static TorMessageDigest createSha3_256() {
		return new TorMessageDigest(Algorithm.SHA3_256);
	}

	private MessageDigest createDigestInstance(boolean isDigest256) {
		try {
			final String algorithm = (isDigest256) ? TOR_DIGEST256_ALGORITHM : TOR_DIGEST_ALGORITHM;
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Return <tt>true</tt> if this is a 256 bit digest instance.
	 *
	 * @return <tt>true</tt> if this is a 256 bit digest instance.
	 */
	public boolean isDigest256() {
		return algorithm != Algorithm.SHA1;
	}

	public Algorithm getAlgorithm() {
		return algorithm;
	}

	/**
	 * Return the digest size in bytes for this instance.
	 */
	public int getDigestSize() {
		return isDigest256() ? TOR_DIGEST256_SIZE : TOR_DIGEST_SIZE;
	}

	/**
	 * Return the digest value of all data processed up until this point.
	 * @return The digest value as an array of <code>TOR_DIGEST_SIZE<code> or <code>TOR_DIGEST256_SIZE</code> bytes.
	 */
	public byte[] getDigestBytes() {
		if(keccakInstance != null) {
			return keccakInstance.copy().digest();
		}
		try {
			// Make a clone because #digest() will reset the MessageDigest instance
			// and we want to be able to use this class for running digests on circuits
			final MessageDigest clone = (MessageDigest) digestInstance.clone();
			return clone.digest();
		} catch (CloneNotSupportedException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Return what the digest for the current running hash would be IF we
	 * added <code>data</code>, but don't really add the data to the digest
	 * calculation.
	 */
	public byte[] peekDigest(byte[] data, int offset, int length) {
		if(keccakInstance != null) {
			return keccakInstance.copy().update(data, offset, length).digest();
		}
		try {
			final MessageDigest clone = (MessageDigest) digestInstance.clone();
			clone.update(data, offset, length);
			return clone.digest();
		} catch (CloneNotSupportedException e) {
			throw new TorException(e);
		}
	}

	/**
	 * Calculate the digest value of all data processed up until this point and convert
	 * the digest into a <code>HexDigest</code> object.
	 * @return A new <code>HexDigest</code> object representing the current digest value.
	 * @see HexDigest
	 */
	public HexDigest getHexDigest() {
		return HexDigest.createFromDigestBytes(getDigestBytes());
	}

	/**
	 * Add the entire contents of the byte array <code>input</code> to the current digest calculation.
	 *
	 * @param input An array of input bytes to process.
	 */
	public void update(byte[] input) {
		update(input, 0, input.length);
	}

	/**
	 * Add <code>length</code> bytes of the contents of the byte array <code>input</code> beginning at
	 * <code>offset</code> into the array to the current digest calculation.
	 *
	 * @param input An array of input bytes to process.
	 * @param offset The offset into the <code>input</code> array to begin processing.
	 * @param length A count of how many bytes of the <code>input</code> array to process.
	 */
	public void update(byte[] input, int offset, int length) {
		if(keccakInstance != null) {
			keccakInstance.update(input, offset, length);
		} else {
			digestInstance.update(input, offset, length);
		}
	}

	/**
	 * Convert the String <code>input</code> into an array of bytes using the ISO-8859-1 encoding
	 * and add these bytes to the current digest calculation.
	 *
	 * @param input A string to process.
	 */
	public void update(String input) {
		try {
			update(input.getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			throw new TorException(e);
		}
	}

}
