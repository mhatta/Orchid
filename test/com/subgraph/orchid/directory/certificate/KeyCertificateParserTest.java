package com.subgraph.orchid.directory.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.crypto.TorPrivateKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.directory.TestAuthority;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;

public class KeyCertificateParserTest {

	@Test
	public void testValidCertificate() {
		final TestAuthority authority = new TestAuthority();
		final TorPrivateKey signingKey = authority.newSigningKey();
		final KeyCertificate cert = TestAuthority.parseCertificate(authority.certificate(signingKey, 1));
		assertEquals(authority.getFingerprint(), cert.getAuthorityFingerprint());
		assertEquals(signingKey.getPublicKey().getFingerprint(), cert.getAuthoritySigningKey().getFingerprint());
	}

	/*
	 * A certificate made with someone else's keys but labelled with the
	 * fingerprint of a trusted authority (here: moria1) must be rejected.
	 */
	@Test
	public void testCertificateForAnotherFingerprintIsRejected() {
		final TestAuthority impostor = new TestAuthority();
		final HexDigest moria1 = HexDigest.createFromString("F533C81CEF0BC0267857C99B2F471ADF249FA232");
		final String forged = impostor.certificate(moria1, impostor.newSigningKey(), 1, impostor.getIdentityKey());
		final BasicDocumentParsingResult<KeyCertificate> result = TestAuthority.parseCertificates(forged);
		assertTrue(result.isInvalid());
		assertTrue(result.getParsedDocuments().isEmpty());
	}

	/* A certification signature made with the wrong key is a failed signature, not an exception. */
	@Test
	public void testCertificateSignedWithWrongKeyIsRejected() {
		final TestAuthority authority = new TestAuthority();
		final TorPrivateKey other = TorPrivateKey.generateNewKeypair();
		final String bad = authority.certificate(authority.getFingerprint(), authority.newSigningKey(), 1, other);
		final BasicDocumentParsingResult<KeyCertificate> result = TestAuthority.parseCertificates(bad);
		assertTrue(result.isInvalid());
		assertTrue(result.getParsedDocuments().isEmpty());
	}

	/* One bad certificate in a response does not hide the good ones. */
	@Test
	public void testGoodCertificatesSurviveABadOne() {
		final TestAuthority a = new TestAuthority();
		final TestAuthority b = new TestAuthority();
		final String forged = b.certificate(a.getFingerprint(), b.newSigningKey(), 1, b.getIdentityKey());
		final String text = a.certificate(a.newSigningKey(), 1) + forged + b.certificate(b.newSigningKey(), 1);
		final BasicDocumentParsingResult<KeyCertificate> result = TestAuthority.parseCertificates(text);
		assertEquals(2, result.getParsedDocuments().size());
	}
}
