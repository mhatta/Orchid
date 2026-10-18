package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.SecureRandom;

import org.junit.Test;

import com.subgraph.orchid.encoders.Hex;

/**
 * hs-ntor tests.  The fixed vectors are the [NTOR-WITH-EXTRA-DATA] test
 * vectors published in rend-spec-v3 appendix "Test vectors" (generated from
 * the C Tor implementation).
 */
public class HSNtorKeyAgreementTest {

	static byte[] unhex(String s) {
		return Hex.decode(s);
	}

	static String hex(byte[] b) {
		return new String(Hex.encode(b)).toUpperCase();
	}

	/* Service side values */
	static final byte[] KP_HS_IPD_SID = unhex("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
	static final byte[] KP_HSS_NTOR = unhex("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979");
	static final byte[] KS_HSS_NTOR = unhex("A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A");
	static final byte[] N_HS_SUBCRED = unhex("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57");
	/* Client side values */
	static final byte[] CLIENT_X_SECRET = unhex("60B4D6BF5234DCF87A4E9D7487BDF3F4A69B6729835E825CA29089CFDDA1E341");
	static final byte[] CLIENT_X_PUBLIC = unhex("BF04348B46D09AED726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5D");
	static final byte[] ENC_KEY = unhex("9B8917BA3D05F3130DACCE5300C3DC27F6D012912F1C733036F822D0ED238706");
	static final byte[] MAC_KEY = unhex("FC4058DA59D4DF61E7B40985D122F502FD59336BC21C30CAF5E7F0D4A2C38FD5");
	/* Service ephemeral key and handshake outputs */
	static final byte[] SERVICE_Y_SECRET = unhex("68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55");
	static final byte[] SERVICE_Y_PUBLIC = unhex("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700");
	static final byte[] AUTH_INPUT_MAC = unhex("4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208");
	static final byte[] NTOR_KEY_SEED = unhex("4D0C72FE8AFF35559D95ECC18EB5A36883402B28CDFD48C8A530A5A3D7D578DB");

	@Test
	public void testIntroduce1KeyDerivationVectors() {
		final HSNtorKeyAgreement kex = new HSNtorKeyAgreement(KP_HS_IPD_SID, KP_HSS_NTOR, N_HS_SUBCRED, CLIENT_X_SECRET);
		assertEquals(hex(CLIENT_X_PUBLIC), hex(kex.getClientPublicKey()));
		assertEquals(hex(ENC_KEY), hex(kex.getIntroduceEncKey()));
		assertEquals(hex(MAC_KEY), hex(kex.getIntroduceMacKey()));
	}

	@Test
	public void testRendezvousCompletionVectors() {
		final HSNtorKeyAgreement kex = new HSNtorKeyAgreement(KP_HS_IPD_SID, KP_HSS_NTOR, N_HS_SUBCRED, CLIENT_X_SECRET);
		final byte[] keys = kex.completeHandshake(SERVICE_Y_PUBLIC, AUTH_INPUT_MAC);
		assertNotNull("AUTH_INPUT_MAC from the test vectors must verify", keys);
		assertEquals(HSNtorKeyAgreement.KEY_EXPANSION_LEN, keys.length);
		assertArrayEquals(HSNtorKeyAgreement.expandKeys(NTOR_KEY_SEED), keys);

		final byte[] badAuth = AUTH_INPUT_MAC.clone();
		badAuth[0] ^= 1;
		assertNull(kex.completeHandshake(SERVICE_Y_PUBLIC, badAuth));
	}

	/**
	 * Simulate the service side (as hs_ntor_ref.py does) and check that both
	 * sides agree, for random keys.
	 */
	@Test
	public void testFullHandshakeAgainstSimulatedService() {
		final SecureRandom rng = new SecureRandom();
		for(int i = 0; i < 5; i++) {
			final byte[] authKey = new byte[32];
			rng.nextBytes(authKey);
			final byte[] subcred = new byte[32];
			rng.nextBytes(subcred);
			final byte[] b = HSNtorKeyAgreement.generateSecretKey();
			final byte[] B = new byte[32];
			Curve25519.crypto_scalarmult_base(B, b);

			final HSNtorKeyAgreement client = new HSNtorKeyAgreement(authKey, B, subcred);
			final byte[] X = client.getClientPublicKey();

			/* Service: intro keys from EXP(X,b) */
			final byte[] expXb = HSNtorKeyAgreement.scalarMult(b, X);
			final byte[] introSecretInput = HSNtorKeyAgreement.concat(expXb, authKey, X, B, HSNtorKeyAgreement.PROTOID_BYTES);
			final byte[] info = HSNtorKeyAgreement.concat(HSNtorKeyAgreement.M_HSEXPAND, subcred);
			final byte[] hsKeys = Keccak.shake256(64, introSecretInput, HSNtorKeyAgreement.T_HSENC, info);
			assertEquals(hex(java.util.Arrays.copyOfRange(hsKeys, 0, 32)), hex(client.getIntroduceEncKey()));
			assertEquals(hex(java.util.Arrays.copyOfRange(hsKeys, 32, 64)), hex(client.getIntroduceMacKey()));

			/* Service: rendezvous keys */
			final byte[] y = HSNtorKeyAgreement.generateSecretKey();
			final byte[] Y = new byte[32];
			Curve25519.crypto_scalarmult_base(Y, y);
			final byte[] expXy = HSNtorKeyAgreement.scalarMult(y, X);
			final byte[] rendSecretInput = HSNtorKeyAgreement.concat(expXy, expXb, authKey, B, X, Y, HSNtorKeyAgreement.PROTOID_BYTES);
			final byte[] seed = HSNtorKeyAgreement.mac(rendSecretInput, HSNtorKeyAgreement.T_HSENC);
			final byte[] verify = HSNtorKeyAgreement.mac(rendSecretInput, HSNtorKeyAgreement.T_HSVERIFY);
			final byte[] authInput = HSNtorKeyAgreement.concat(verify, authKey, B, Y, X, HSNtorKeyAgreement.PROTOID_BYTES, HSNtorKeyAgreement.SERVER_STR);
			final byte[] auth = HSNtorKeyAgreement.mac(authInput, HSNtorKeyAgreement.T_HSMAC);

			final byte[] clientKeys = client.completeHandshake(Y, auth);
			assertNotNull(clientKeys);
			assertArrayEquals(HSNtorKeyAgreement.expandKeys(seed), clientKeys);
		}
	}

	@Test
	public void testMacDefinition() {
		/* MAC(key, msg) = SHA3-256(INT_8(len(key)) | key | msg) */
		final byte[] key = new byte[] { 1, 2, 3 };
		final byte[] msg = new byte[] { 9 };
		final byte[] expected = Keccak.digestSha3_256(new byte[] { 0, 0, 0, 0, 0, 0, 0, 3 }, key, msg);
		assertArrayEquals(expected, HSNtorKeyAgreement.mac(key, msg));
		assertEquals("0000000000000539", hex(HSNtorKeyAgreement.int8(1337)).toLowerCase());
	}
}
