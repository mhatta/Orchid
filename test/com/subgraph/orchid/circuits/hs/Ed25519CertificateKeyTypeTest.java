package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;

import org.junit.Test;

import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.crypto.Ed25519TestSigner;

/**
 * The certificates of v3 onion service descriptors certify Ed25519 keys.  A
 * certificate whose CERT_KEY_TYPE says otherwise is the wrong one, even if
 * its signature is good.
 */
public class Ed25519CertificateKeyTypeTest {
	private static final long NOW = 1800000000L;

	@Test
	public void testCertifiedKeyTypeMustBeEd25519() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(27000, 1440, NOW, 1);
		final Ed25519TestSigner signer = Ed25519TestSigner.random(new SecureRandom());
		final byte[] key = new byte[32];
		final long expiration = NOW / 3600 + 24;
		final int type = Ed25519Certificate.CERT_TYPE_HS_IP_V_SIGNING;

		final Ed25519Certificate good = Ed25519Certificate.parse(svc.encodeCert(type, key, signer, expiration));
		assertTrue(good.isValid(type, signer.publicKey, NOW));

		final Ed25519Certificate rsaDigest = Ed25519Certificate.parse(svc.encodeCert(type, key, signer, expiration, 2));
		assertFalse(rsaDigest.isValid(type, signer.publicKey, NOW));
	}
}
