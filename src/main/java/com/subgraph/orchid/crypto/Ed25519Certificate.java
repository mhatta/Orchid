package com.subgraph.orchid.crypto;

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.subgraph.orchid.TorParsingException;

/**
 * An Ed25519 certificate in the binary format of cert-spec ("Ed25519
 * certificates" / proposal 220):
 * <pre>
 *   VERSION         [1 Byte]   (always 1)
 *   CERT_TYPE       [1 Byte]
 *   EXPIRATION_DATE [4 Bytes]  hours since the epoch, big endian
 *   CERT_KEY_TYPE   [1 byte]   (1 = ed25519)
 *   CERTIFIED_KEY   [32 Bytes]
 *   N_EXTENSIONS    [1 byte]
 *   EXTENSION       [N_EXTENSIONS times]
 *       ExtLength [2 bytes]
 *       ExtType   [1 byte]
 *       ExtFlags  [1 byte]
 *       ExtData   [ExtLength bytes]
 *   SIGNATURE       [64 Bytes]
 * </pre>
 * The only extension defined is type 4 ("signed-with-ed25519-key") whose data
 * is the 32 byte key that signed the certificate.
 */
public final class Ed25519Certificate {
	public static final int VERSION = 1;
	public static final int KEY_TYPE_ED25519 = 1;
	public static final int EXT_TYPE_SIGNED_WITH_ED25519_KEY = 4;
	public static final int EXT_FLAG_AFFECTS_VALIDATION = 1;

	/** Cert types used by the v3 onion service protocol (rend-spec-v3 appendix E). */
	public static final int CERT_TYPE_HS_DESC_SIGNING = 0x08;   /* descriptor signing key, signed with blinded key */
	public static final int CERT_TYPE_HS_IP_V_SIGNING = 0x09;   /* intro point auth key, signed with descriptor signing key */
	public static final int CERT_TYPE_HS_IP_CC_SIGNING = 0x0B;  /* intro point enc key cross-cert, signed with descriptor signing key */

	private final int certType;
	private final long expirationHours;
	private final int certifiedKeyType;
	private final byte[] certifiedKey;
	private final byte[] signingKey; /* from the signed-with-ed25519-key extension, may be null */
	private final byte[] signature;
	private final byte[] signedBody;
	private final boolean hasUnknownValidationAffectingExtension;

	private Ed25519Certificate(int certType, long expirationHours, int certifiedKeyType, byte[] certifiedKey,
			byte[] signingKey, byte[] signature, byte[] signedBody, boolean unknownExt) {
		this.certType = certType;
		this.expirationHours = expirationHours;
		this.certifiedKeyType = certifiedKeyType;
		this.certifiedKey = certifiedKey;
		this.signingKey = signingKey;
		this.signature = signature;
		this.signedBody = signedBody;
		this.hasUnknownValidationAffectingExtension = unknownExt;
	}

	/**
	 * Parse the binary certificate.
	 *
	 * @throws TorParsingException if the encoding is malformed.
	 */
	public static Ed25519Certificate parse(byte[] encoded) {
		if(encoded == null || encoded.length < 1 + 1 + 4 + 1 + 32 + 1 + 64) {
			throw new TorParsingException("Ed25519 certificate too short");
		}
		final ByteBuffer bb = ByteBuffer.wrap(encoded);
		final int version = bb.get() & 0xFF;
		if(version != VERSION) {
			throw new TorParsingException("Unsupported Ed25519 certificate version "+ version);
		}
		final int certType = bb.get() & 0xFF;
		final long expiration = bb.getInt() & 0xFFFFFFFFL;
		final int keyType = bb.get() & 0xFF;
		final byte[] certifiedKey = new byte[32];
		bb.get(certifiedKey);
		final int nExtensions = bb.get() & 0xFF;
		byte[] signingKey = null;
		boolean unknownExt = false;
		for(int i = 0; i < nExtensions; i++) {
			if(bb.remaining() < 4 + 64) {
				throw new TorParsingException("Truncated Ed25519 certificate extension");
			}
			final int extLength = bb.getShort() & 0xFFFF;
			final int extType = bb.get() & 0xFF;
			final int extFlags = bb.get() & 0xFF;
			if(bb.remaining() < extLength + 64) {
				throw new TorParsingException("Truncated Ed25519 certificate extension data");
			}
			final byte[] extData = new byte[extLength];
			bb.get(extData);
			if(extType == EXT_TYPE_SIGNED_WITH_ED25519_KEY) {
				if(extLength != 32) {
					throw new TorParsingException("Invalid length for signed-with-ed25519-key extension: "+ extLength);
				}
				if(signingKey != null) {
					throw new TorParsingException("Duplicate signed-with-ed25519-key extension");
				}
				signingKey = extData;
			} else if((extFlags & EXT_FLAG_AFFECTS_VALIDATION) != 0) {
				unknownExt = true;
			}
		}
		if(bb.remaining() != 64) {
			throw new TorParsingException("Unexpected trailing data in Ed25519 certificate");
		}
		final int bodyLen = bb.position();
		final byte[] signature = new byte[64];
		bb.get(signature);
		final byte[] body = Arrays.copyOf(encoded, bodyLen);
		return new Ed25519Certificate(certType, expiration, keyType, certifiedKey, signingKey, signature, body, unknownExt);
	}

	public int getCertType() {
		return certType;
	}

	/** Expiration time in hours since the epoch. */
	public long getExpirationHours() {
		return expirationHours;
	}

	/** Expiration time in seconds since the epoch. */
	public long getExpirationSeconds() {
		return expirationHours * 3600L;
	}

	public boolean isExpiredAt(long nowSeconds) {
		return getExpirationSeconds() < nowSeconds;
	}

	public int getCertifiedKeyType() {
		return certifiedKeyType;
	}

	/** The key (or key digest) this certificate certifies. */
	public byte[] getCertifiedKey() {
		return certifiedKey.clone();
	}

	/** The signing key from the signed-with-ed25519-key extension, or null if absent. */
	public byte[] getSigningKey() {
		return signingKey == null ? null : signingKey.clone();
	}

	public boolean hasSigningKeyExtension() {
		return signingKey != null;
	}

	/**
	 * Verify the certificate signature with the given signing key.  Returns
	 * false if the certificate contains an unknown extension that affects
	 * validation.
	 */
	public boolean verifySignature(byte[] signingPublicKey) {
		if(hasUnknownValidationAffectingExtension || signingPublicKey == null) {
			return false;
		}
		return Ed25519.verify(signingPublicKey, signedBody, signature);
	}

	/**
	 * Convenience check used by the v3 descriptor parser: the certificate must
	 * have the expected type, carry a signing-key extension equal to
	 * <code>expectedSigningKey</code> (when non-null), verify under that key and
	 * not be expired.
	 */
	public boolean isValid(int expectedCertType, byte[] expectedSigningKey, long nowSeconds) {
		if(certType != expectedCertType) {
			return false;
		}
		if(signingKey == null) {
			return false;
		}
		if(expectedSigningKey != null && !Arrays.equals(expectedSigningKey, signingKey)) {
			return false;
		}
		if(isExpiredAt(nowSeconds)) {
			return false;
		}
		return verifySignature(signingKey);
	}
}
