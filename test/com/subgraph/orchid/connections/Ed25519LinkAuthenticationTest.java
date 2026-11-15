package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import org.junit.BeforeClass;
import org.junit.Test;

import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.crypto.Ed25519TestSigner;

/**
 * The Ed25519 checks of the CERTS cell, with certificates made as a relay
 * makes them: identity -> signing key (type 4), signing key -> TLS link
 * (type 5) and the RSA -> Ed25519 cross certificate (type 7).
 */
public class Ed25519LinkAuthenticationTest {
	private static final long NOW = 1800000000L;
	private static final long HOUR = 3600L;

	private static final SecureRandom rng = new SecureRandom(new byte[] { 1, 2, 3 });
	private static KeyPair rsa;
	private static KeyPair otherRsa;
	private static Ed25519TestSigner identity;
	private static Ed25519TestSigner signing;
	private static Ed25519TestSigner stranger;
	private static final byte[] TLS_CERT = "the DER of the TLS certificate".getBytes(StandardCharsets.US_ASCII);

	@BeforeClass
	public static void keys() throws Exception {
		final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(1024, rng);
		rsa = g.generateKeyPair();
		otherRsa = g.generateKeyPair();
		identity = Ed25519TestSigner.random(rng);
		signing = Ed25519TestSigner.random(rng);
		stranger = Ed25519TestSigner.random(rng);
	}

	/* An Ed25519 certificate; signedWith is put in a signed-with-ed25519-key extension if not null. */
	static byte[] edCert(int certType, long expiresSeconds, int keyType, byte[] certified, byte[] signedWith,
			Ed25519TestSigner signer) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(1);
		out.write(certType);
		final long hours = expiresSeconds / HOUR;
		out.write((int) (hours >> 24));
		out.write((int) (hours >> 16));
		out.write((int) (hours >> 8));
		out.write((int) hours);
		out.write(keyType);
		out.write(certified, 0, 32);
		if(signedWith == null) {
			out.write(0);
		} else {
			out.write(1);
			out.write(0);
			out.write(32);
			out.write(4);
			out.write(0);
			out.write(signedWith, 0, 32);
		}
		final byte[] body = out.toByteArray();
		final byte[] sig = signer.sign(body);
		out.write(sig, 0, sig.length);
		return out.toByteArray();
	}

	static byte[] crossCert(byte[] edIdentity, long expiresSeconds, KeyPair rsaKey) throws Exception {
		final ByteBuffer signed = ByteBuffer.allocate(36);
		signed.put(edIdentity);
		signed.putInt((int) (expiresSeconds / HOUR));
		final MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(Ed25519LinkAuthentication.CROSSCERT_PREFIX.getBytes(StandardCharsets.US_ASCII));
		md.update(signed.array());
		final Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		c.init(Cipher.ENCRYPT_MODE, rsaKey.getPrivate());
		final byte[] sig = c.doFinal(md.digest());
		final ByteBuffer out = ByteBuffer.allocate(36 + 1 + sig.length);
		out.put(signed.array());
		out.put((byte) sig.length);
		out.put(sig);
		return out.array();
	}

	private static byte[] goodSigning() {
		return edCert(4, NOW + 30 * 24 * HOUR, 1, signing.publicKey, identity.publicKey, identity);
	}

	private static byte[] goodLink() {
		return edCert(5, NOW + 48 * HOUR, 3, Ed25519LinkAuthentication.sha256(TLS_CERT), null, signing);
	}

	private static byte[] goodCross() throws Exception {
		return crossCert(identity.publicKey, NOW + 365 * 24 * HOUR, rsa);
	}

	private static byte[] verify(byte[] s, byte[] l, byte[] x) throws ConnectionHandshakeException {
		return Ed25519LinkAuthentication.verify(s, l, x, (RSAPublicKey) rsa.getPublic(), TLS_CERT, NOW);
	}

	private static void assertRejected(String messagePart, byte[] s, byte[] l, byte[] x) {
		try {
			verify(s, l, x);
			fail("expected ConnectionHandshakeException");
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage(), e.getMessage().contains(messagePart));
		}
	}

	@Test
	public void validCertificates() throws Exception {
		assertArrayEquals(identity.publicKey, verify(goodSigning(), goodLink(), goodCross()));
	}

	@Test
	public void linkCertificateMayNameItsSigner() throws Exception {
		final byte[] link = edCert(5, NOW + HOUR, 3, Ed25519LinkAuthentication.sha256(TLS_CERT), signing.publicKey, signing);
		assertArrayEquals(identity.publicKey, verify(goodSigning(), link, goodCross()));
	}

	@Test
	public void missingCertificate() throws Exception {
		assertRejected("lacks", goodSigning(), null, goodCross());
	}

	@Test
	public void signingCertificateWithoutIdentity() throws Exception {
		assertRejected("does not name", edCert(4, NOW + HOUR, 1, signing.publicKey, null, identity), goodLink(), goodCross());
	}

	@Test
	public void signingCertificateSignedByAnotherKey() throws Exception {
		assertRejected("Bad signature on Ed25519 signing", edCert(4, NOW + HOUR, 1, signing.publicKey, identity.publicKey, stranger),
				goodLink(), goodCross());
	}

	@Test
	public void certificateTypesAreChecked() throws Exception {
		assertRejected("type 4", edCert(5, NOW + HOUR, 1, signing.publicKey, identity.publicKey, identity), goodLink(), goodCross());
		assertRejected("type 5", goodSigning(), edCert(5, NOW + HOUR, 1, Ed25519LinkAuthentication.sha256(TLS_CERT), null, signing), goodCross());
		assertRejected("type 5", goodSigning(), goodSigning(), goodCross());
	}

	@Test
	public void expiredCertificates() throws Exception {
		assertRejected("signing key certificate has expired", edCert(4, NOW - HOUR, 1, signing.publicKey, identity.publicKey, identity),
				goodLink(), goodCross());
		assertRejected("TLS link certificate has expired", goodSigning(),
				edCert(5, NOW - HOUR, 3, Ed25519LinkAuthentication.sha256(TLS_CERT), null, signing), goodCross());
		assertRejected("cross certificate has expired", goodSigning(), goodLink(), crossCert(identity.publicKey, NOW - HOUR, rsa));
	}

	@Test
	public void linkCertificateSignedByAnotherKey() throws Exception {
		assertRejected("Bad signature on Ed25519 TLS link", goodSigning(),
				edCert(5, NOW + HOUR, 3, Ed25519LinkAuthentication.sha256(TLS_CERT), null, stranger), goodCross());
		assertRejected("names another signing key", goodSigning(),
				edCert(5, NOW + HOUR, 3, Ed25519LinkAuthentication.sha256(TLS_CERT), stranger.publicKey, stranger), goodCross());
	}

	@Test
	public void linkCertificateForAnotherTlsCertificate() throws Exception {
		final byte[] other = Ed25519LinkAuthentication.sha256("another certificate".getBytes(StandardCharsets.US_ASCII));
		assertRejected("does not match the TLS certificate", goodSigning(), edCert(5, NOW + HOUR, 3, other, null, signing), goodCross());
		try {
			Ed25519LinkAuthentication.verify(goodSigning(), goodLink(), goodCross(), (RSAPublicKey) rsa.getPublic(), null, NOW);
			fail();
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage().contains("does not match the TLS certificate"));
		}
	}

	@Test
	public void crossCertificateForAnotherIdentity() throws Exception {
		assertRejected("names another Ed25519 identity", goodSigning(), goodLink(), crossCert(stranger.publicKey, NOW + HOUR, rsa));
	}

	@Test
	public void crossCertificateSignedByAnotherRsaKey() throws Exception {
		assertRejected("Bad signature on RSA", goodSigning(), goodLink(), crossCert(identity.publicKey, NOW + HOUR, otherRsa));
	}

	@Test
	public void malformedCertificates() throws Exception {
		assertRejected("Malformed", new byte[10], goodLink(), goodCross());
		assertRejected("too short", goodSigning(), goodLink(), new byte[20]);
		final byte[] cross = goodCross();
		final byte[] truncated = java.util.Arrays.copyOf(cross, cross.length - 1);
		assertRejected("signature length", goodSigning(), goodLink(), truncated);
	}

	/* The decision in ConnectionHandshakeV3 around the checks above. */

	private static ConnectionHandshakeV3.CertsCell certs(byte[] s, byte[] l, byte[] x) {
		final ConnectionHandshakeV3.CertsCell c = new ConnectionHandshakeV3.CertsCell();
		c.ed25519SigningCertificate = s;
		c.ed25519TlsLinkCertificate = l;
		c.rsaEd25519CrossCertificate = x;
		return c;
	}

	private static byte[] check(ConnectionHandshakeV3.CertsCell c, byte[] expected) throws ConnectionHandshakeException {
		return ConnectionHandshakeV3.checkEd25519Identity(c, expected, (RSAPublicKey) rsa.getPublic(), TLS_CERT, NOW);
	}

	@Test
	public void identityMustMatchDirectory() throws Exception {
		final ConnectionHandshakeV3.CertsCell c = certs(goodSigning(), goodLink(), goodCross());
		assertArrayEquals(identity.publicKey, check(c, identity.publicKey));
		assertArrayEquals(identity.publicKey, check(c, null));
		try {
			check(c, stranger.publicKey);
			fail();
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage().contains("does not match"));
		}
	}

	@Test
	public void listedIdentityNeedsEd25519Certificates() throws Exception {
		assertNull(check(certs(null, null, null), null));
		try {
			check(certs(null, null, null), identity.publicKey);
			fail();
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage().contains("sent no Ed25519"));
		}
	}

	@Test
	public void partialEd25519CertificatesAreRejected() throws Exception {
		try {
			check(certs(goodSigning(), null, null), null);
			fail();
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage().contains("lacks"));
		}
	}
}
