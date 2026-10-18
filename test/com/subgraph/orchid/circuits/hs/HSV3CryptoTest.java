package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.encoders.Hex;

/**
 * Test vectors for the v3 onion service key derivations.  Vectors come from
 * the C Tor test suite (test_hs_common.c, hs_build_address.py, hs_indexes.py).
 */
public class HSV3CryptoTest {

	static byte[] unhex(String s) {
		return Hex.decode(s);
	}

	static String hex(byte[] b) {
		return new String(Hex.encode(b)).toUpperCase();
	}

	static final byte[] IDENTITY_KEY = unhex("833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6");

	@Test
	public void testBlindingParameterAndBlindedKey() {
		final byte[] param = HSV3Crypto.blindingParameter(IDENTITY_KEY, 1234, 1440);
		assertEquals("379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287", hex(param));
		final byte[] blinded = HSV3Crypto.blindedPublicKey(IDENTITY_KEY, 1234, 1440);
		assertEquals("3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5", hex(blinded));
		final byte[] subcred = HSV3Crypto.subcredential(IDENTITY_KEY, blinded);
		assertEquals("635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D", hex(subcred));
	}

	@Test
	public void testIndexes() {
		/* hs_indexes.py */
		final byte[] identity = new byte[32];
		Arrays.fill(identity, (byte) 0x42);
		final byte[] srv = new byte[32];
		Arrays.fill(srv, (byte) 0x43);
		assertEquals("DB475361014A09965E7E5E4D4A25B8F8D4B8F16CB1D8A7E95EED50249CC1A2D5", hex(HSV3Crypto.hsdirIndex(identity, srv, 42, 1440)));
		assertEquals("37E5CBBD56A22823714F18F1623ECE5983A0D64C78495A8CFAB854245E5F9A8A", hex(HSV3Crypto.hsIndex(1, identity, 1440, 42)));
	}

	@Test
	public void testDisasterSharedRandomValue() {
		assertEquals("8CECEEE08EB4F1D74CAB263116E8AEBC2845A6A386104AA9144237584C856531", hex(HSV3Crypto.disasterSharedRandomValue(1440, 42)));
	}

	@Test
	public void testOnionAddressBuild() {
		/* hs_build_address.py: ed25519 public key from RFC 8032 test vector 1 */
		final byte[] pubkey = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
		assertEquals("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid", HSV3Address.encode(pubkey));
		final HSV3Address parsed = HSV3Address.parse("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion");
		assertEquals(hex(pubkey), hex(parsed.getPublicKey()));
		assertEquals("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion", parsed.getOnionAddress());
		/* case insensitive, suffix optional */
		assertEquals(parsed, HSV3Address.parse("25NJQAMCWEFLPVKL73J4SZAHHIHOC4XT3KTCGJNPAINGR5YHKENL5SID"));
	}

	@Test
	public void testOnionAddressValidation() {
		assertFalse(HSV3Address.isV3AddressLength("blah"));
		assertFalse(HSV3Address.isV3AddressLength("3t43tfluce4qcxbo.onion"));
		assertTrue(HSV3Address.isV3AddressLength("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion"));
		expectInvalid("blah");
		expectInvalid("p3xnclpu4mu22dwaurjtsybyqk4xfjmcfz6z62yl24uwmhjatiwnlnadb");
		/* invalid checksum vectors from tor's test_validate_address */
		expectInvalid("l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad");
		expectInvalid("btojiu7nu5y5iwut64eufevogqdw4wmqzugnoluw232r4t3ecsfv37ad");
		expectInvalid("????????????????????????????????????????????????????????");
	}

	private static void expectInvalid(String address) {
		try {
			HSV3Address.parse(address);
			fail("Expected address to be rejected: "+ address);
		} catch (TorException e) {
			// expected
		}
	}
}
