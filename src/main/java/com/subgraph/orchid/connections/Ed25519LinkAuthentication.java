package com.subgraph.orchid.connections;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;

import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.Ed25519;
import com.subgraph.orchid.crypto.Ed25519Certificate;

/**
 * Authentication of a relay's Ed25519 identity from the certificates of its
 * CERTS cell (tor-spec, "Validating a relay's CERTS cell"):
 *
 * <ul>
 * <li>the identity to signing key certificate (CERTS type 4, Ed25519
 *     certificate type 04) names the Ed25519 identity in its
 *     signed-with-ed25519-key extension and is signed by it;</li>
 * <li>the signing key to TLS link certificate (CERTS type 5, Ed25519
 *     certificate type 05) certifies the SHA-256 digest of the X.509
 *     certificate of this TLS connection and is signed by the signing
 *     key;</li>
 * <li>the RSA to Ed25519 cross certificate (CERTS type 7) names the same
 *     Ed25519 identity and is signed by the RSA identity key of the
 *     CERTS cell;</li>
 * <li>none of them has expired.</li>
 * </ul>
 *
 * Together these bind the TLS connection to the Ed25519 identity and the
 * RSA identity at once, so that the caller can compare the Ed25519 identity
 * with the one in the consensus.
 */
final class Ed25519LinkAuthentication {
	/** Ed25519 certificate types (cert-spec, "Certificate types"). */
	static final int ED_CERT_TYPE_IDENTITY_SIGNING = 0x04;
	static final int ED_CERT_TYPE_SIGNING_TLS_LINK = 0x05;
	/** Certified key type: SHA-256 digest of an X.509 certificate. */
	static final int KEY_TYPE_SHA256_OF_X509 = 3;

	static final String CROSSCERT_PREFIX = "Tor TLS RSA/Ed25519 cross-certificate";

	private Ed25519LinkAuthentication() {}

	/**
	 * Check the Ed25519 certificates of a CERTS cell.
	 *
	 * @param signingCert the CERTS type 4 certificate
	 * @param tlsLinkCert the CERTS type 5 certificate
	 * @param crossCert the CERTS type 7 certificate
	 * @param rsaIdentity the RSA identity key, from the CERTS type 2
	 *        certificate, already checked by the caller
	 * @param tlsCertificate the DER encoding of the certificate the relay
	 *        presented in the TLS handshake of this connection
	 * @param nowSeconds the current time, in seconds since the epoch
	 * @return the authenticated Ed25519 identity key (32 bytes)
	 * @throws ConnectionHandshakeException if a certificate is malformed,
	 *         expired, wrongly signed or does not match the others.
	 */
	static byte[] verify(byte[] signingCert, byte[] tlsLinkCert, byte[] crossCert, RSAPublicKey rsaIdentity,
			byte[] tlsCertificate, long nowSeconds) throws ConnectionHandshakeException {
		if(signingCert == null || tlsLinkCert == null || crossCert == null) {
			throw new ConnectionHandshakeException("CERTS cell lacks an Ed25519 certificate (types 4, 5 and 7 are all needed)");
		}
		final Ed25519Certificate idToSigning = parse(signingCert, "identity to signing key (type 4)");
		final Ed25519Certificate signingToLink = parse(tlsLinkCert, "signing key to TLS link (type 5)");

		/* Type 4: signed by the identity key it names. */
		if(idToSigning.getCertType() != ED_CERT_TYPE_IDENTITY_SIGNING
				|| idToSigning.getCertifiedKeyType() != Ed25519Certificate.KEY_TYPE_ED25519) {
			throw new ConnectionHandshakeException("CERTS type 4 is not an Ed25519 identity to signing key certificate");
		}
		final byte[] identity = idToSigning.getSigningKey();
		if(identity == null) {
			throw new ConnectionHandshakeException("Ed25519 signing key certificate does not name the identity key");
		}
		if(!Ed25519.isValidPublicKey(identity)) {
			throw new ConnectionHandshakeException("Invalid Ed25519 identity key in CERTS cell");
		}
		if(idToSigning.isExpiredAt(nowSeconds)) {
			throw new ConnectionHandshakeException("Ed25519 signing key certificate has expired");
		}
		if(!idToSigning.verifySignature(identity)) {
			throw new ConnectionHandshakeException("Bad signature on Ed25519 signing key certificate");
		}
		final byte[] signingKey = idToSigning.getCertifiedKey();

		/* Type 5: certifies this TLS certificate, signed by the signing key. */
		if(signingToLink.getCertType() != ED_CERT_TYPE_SIGNING_TLS_LINK
				|| signingToLink.getCertifiedKeyType() != KEY_TYPE_SHA256_OF_X509) {
			throw new ConnectionHandshakeException("CERTS type 5 is not an Ed25519 TLS link certificate");
		}
		if(signingToLink.hasSigningKeyExtension() && !Arrays.equals(signingKey, signingToLink.getSigningKey())) {
			throw new ConnectionHandshakeException("Ed25519 TLS link certificate names another signing key");
		}
		if(signingToLink.isExpiredAt(nowSeconds)) {
			throw new ConnectionHandshakeException("Ed25519 TLS link certificate has expired");
		}
		if(!signingToLink.verifySignature(signingKey)) {
			throw new ConnectionHandshakeException("Bad signature on Ed25519 TLS link certificate");
		}
		if(tlsCertificate == null || !MessageDigest.isEqual(sha256(tlsCertificate), signingToLink.getCertifiedKey())) {
			throw new ConnectionHandshakeException("Ed25519 TLS link certificate does not match the TLS certificate of the connection");
		}

		/* Type 7: binds the RSA identity to the same Ed25519 identity. */
		verifyCrossCertificate(crossCert, identity, rsaIdentity, nowSeconds);
		return identity;
	}

	/*
	 * cert-spec, "RSA->Ed25519 cross-certificate":
	 *
	 *   ED25519_KEY      [32 bytes]
	 *   EXPIRATION_DATE  [4 bytes]   hours since the epoch
	 *   SIGLEN           [1 byte]
	 *   SIGNATURE        [SIGLEN bytes]
	 *
	 * SIGNATURE is the PKCS#1 v1.5 signature, without a DigestInfo, of
	 * SHA256("Tor TLS RSA/Ed25519 cross-certificate" | ED25519_KEY |
	 * EXPIRATION_DATE) with the RSA identity key.
	 */
	static void verifyCrossCertificate(byte[] crossCert, byte[] identity, RSAPublicKey rsaIdentity, long nowSeconds)
			throws ConnectionHandshakeException {
		if(crossCert.length < 32 + 4 + 1) {
			throw new ConnectionHandshakeException("RSA to Ed25519 cross certificate too short");
		}
		final ByteBuffer bb = ByteBuffer.wrap(crossCert);
		final byte[] edKey = new byte[32];
		bb.get(edKey);
		final long expirationHours = bb.getInt() & 0xFFFFFFFFL;
		final int sigLen = bb.get() & 0xFF;
		if(bb.remaining() != sigLen) {
			throw new ConnectionHandshakeException("RSA to Ed25519 cross certificate has a bad signature length");
		}
		final byte[] signature = new byte[sigLen];
		bb.get(signature);
		if(!Arrays.equals(edKey, identity)) {
			throw new ConnectionHandshakeException("RSA to Ed25519 cross certificate names another Ed25519 identity");
		}
		if(expirationHours * 3600L < nowSeconds) {
			throw new ConnectionHandshakeException("RSA to Ed25519 cross certificate has expired");
		}
		final MessageDigest md = sha256Digest();
		md.update(CROSSCERT_PREFIX.getBytes(StandardCharsets.US_ASCII));
		md.update(crossCert, 0, 32 + 4);
		if(!verifyRsaDigestSignature(rsaIdentity, md.digest(), signature)) {
			throw new ConnectionHandshakeException("Bad signature on RSA to Ed25519 cross certificate");
		}
	}

	/* Tor's RSA signatures: PKCS#1 v1.5 type 1 padding around the bare digest. */
	private static boolean verifyRsaDigestSignature(RSAPublicKey key, byte[] digest, byte[] signature) {
		try {
			final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			return MessageDigest.isEqual(cipher.doFinal(signature), digest);
		} catch (GeneralSecurityException e) {
			return false;
		}
	}

	private static Ed25519Certificate parse(byte[] encoded, String what) throws ConnectionHandshakeException {
		try {
			return Ed25519Certificate.parse(encoded);
		} catch (TorParsingException e) {
			throw new ConnectionHandshakeException("Malformed Ed25519 "+ what +" certificate in CERTS cell: "+ e.getMessage());
		}
	}

	static byte[] sha256(byte[] data) {
		return sha256Digest().digest(data);
	}

	private static MessageDigest sha256Digest() {
		try {
			return MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}
}
