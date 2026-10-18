package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Test;

import com.subgraph.orchid.encoders.Hex;

public class Ed25519Test {

	static byte[] unhex(String s) {
		return Hex.decode(s);
	}

	static String hex(byte[] b) {
		return new String(Hex.encode(b)).toUpperCase();
	}

	/* RFC 8032 section 7.1, TEST 1 */
	@Test
	public void testRfc8032Vector1() {
		final byte[] pk = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
		final byte[] sig = unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
		assertTrue(Ed25519.verify(pk, new byte[0], sig));
		assertTrue(Ed25519.hasNoTorsionComponent(pk));
		final byte[] bad = sig.clone();
		bad[10] ^= 1;
		assertFalse(Ed25519.verify(pk, new byte[0], bad));
		assertFalse(Ed25519.verify(pk, new byte[] { 1 }, sig));
	}

	/* RFC 8032 section 7.1, TEST 2 */
	@Test
	public void testRfc8032Vector2() {
		final byte[] pk = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
		final byte[] msg = unhex("72");
		final byte[] sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
		assertTrue(Ed25519.verify(pk, msg, sig));
	}

	/* RFC 8032 section 7.1, TEST 3 (two byte message) */
	@Test
	public void testRfc8032Vector3() {
		final byte[] pk = unhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
		final byte[] msg = unhex("af82");
		final byte[] sig = unhex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
		assertTrue(Ed25519.verify(pk, msg, sig));
	}

	@Test
	public void testSmallOrderPointsHaveTorsion() {
		/* The identity (0, 1) is a valid point but has order 1 ... */
		final byte[] identity = unhex("0100000000000000000000000000000000000000000000000000000000000000");
		assertTrue(Ed25519.isValidPublicKey(identity));
		assertTrue(Ed25519.hasNoTorsionComponent(identity)); // l * identity == identity: no torsion by definition
		/* ... (0, -1) has order 2 */
		final byte[] order2 = unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		assertTrue(Ed25519.isValidPublicKey(order2));
		assertFalse(Ed25519.hasNoTorsionComponent(order2));
		/* points with y = 0 have order 4 */
		final byte[] order4 = unhex("0000000000000000000000000000000000000000000000000000000000000000");
		assertTrue(Ed25519.isValidPublicKey(order4));
		assertFalse(Ed25519.hasNoTorsionComponent(order4));
		/* y >= p is not a valid encoding */
		assertFalse(Ed25519.isValidPublicKey(unhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")));
	}

	/* Blinding test vector from tor's test_hs_common.c (test_blinding_basics) */
	@Test
	public void testBlindPublicKeyTorVector() {
		final byte[] pubkey = unhex("833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6");
		final byte[] param = unhex("379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287");
		final byte[] blinded = Ed25519.blindPublicKey(pubkey, Ed25519.clampScalar(param));
		assertEquals("3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5", hex(blinded));
	}

	@Test
	public void testCurve25519ToEd25519Conversion() {
		/* u = 9 (the curve25519 base point) corresponds to the ed25519 base point y = 4/5 */
		final byte[] u9 = new byte[32];
		u9[0] = 9;
		assertEquals("5866666666666666666666666666666666666666666666666666666666666666", hex(Ed25519.fromCurve25519PublicKey(u9, false)).toLowerCase());
		assertEquals("58666666666666666666666666666666666666666666666666666666666666e6", hex(Ed25519.fromCurve25519PublicKey(u9, true)).toLowerCase());
	}

	@Test
	public void testSignerRoundTripAndBlindedSignatures() {
		final SecureRandom rng = new SecureRandom();
		final Ed25519TestSigner signer = Ed25519TestSigner.random(rng);
		final byte[] msg = "hello onion".getBytes();
		final byte[] sig = signer.sign(msg);
		assertTrue(Ed25519.verify(signer.publicKey, msg, sig));
		assertTrue(Ed25519.verifyPrefixed(signer.publicKey, "prefix", msg, 0, msg.length, signer.sign(msg, "prefix")));
		assertFalse(Ed25519.verify(signer.publicKey, msg, signer.sign(msg, "prefix")));

		/* Signing with the blinded scalar verifies under the blinded public key. */
		final byte[] h = Ed25519.clampScalar(unhex("379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287"));
		final Ed25519TestSigner blinded = signer.blind(h);
		assertArrayEquals(Ed25519.blindPublicKey(signer.publicKey, h), blinded.publicKey);
		assertTrue(Ed25519.verify(blinded.publicKey, msg, blinded.sign(msg)));
		assertFalse(Ed25519.verify(signer.publicKey, msg, blinded.sign(msg)));
	}

	@Test
	public void testScalarEncodingRoundTrip() {
		final BigInteger v = new BigInteger("123456789012345678901234567890123456789012345678901234567890");
		assertEquals(v, Ed25519.decodeLittleEndian(Ed25519.encodeLittleEndian(v)));
	}
}
