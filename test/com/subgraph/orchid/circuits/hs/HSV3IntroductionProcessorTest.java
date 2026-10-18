package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.subgraph.orchid.crypto.Curve25519;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.crypto.Keccak;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

public class HSV3IntroductionProcessorTest {

	/**
	 * Build an INTRODUCE1 body and decode it as the service does (rend-spec-v3
	 * 3.2.1 / 3.3), independently re-deriving the keys from the service's
	 * private enc key.
	 */
	@Test
	public void testIntroduce1BodyRoundTrip() throws Exception {
		final SecureRandom rng = new SecureRandom();
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(27000, 1440, 1704891600L, 1);
		final HSV3TestServiceEncoder.IntroPoint ipData = svc.addIntroPoint(9001);
		final HSV3Descriptor desc = new HSV3DescriptorParser(svc.blinded.publicKey, svc.subcredential, null, 1704891600L, 27000).parse(svc.encodeDescriptor());
		final HSV3IntroductionPoint ip = desc.getIntroductionPoints().get(0);

		final HSV3IntroductionProcessor processor = new HSV3IntroductionProcessor(null, null, ip);
		final HSNtorKeyAgreement kex = new HSNtorKeyAgreement(ip.getAuthKey(), ip.getEncKey(), svc.subcredential);
		final byte[] cookie = new byte[20];
		rng.nextBytes(cookie);
		final byte[] rpOnionKey = new byte[32];
		rng.nextBytes(rpOnionKey);
		final byte[] rpId = new byte[20];
		rng.nextBytes(rpId);
		final byte[] rpEd = new byte[32];
		rng.nextBytes(rpEd);
		final List<LinkSpecifier> rpSpecs = Arrays.asList(
				LinkSpecifier.ipv4(IPv4Address.createFromString("10.1.2.3"), 9001),
				LinkSpecifier.legacyId(HexDigest.createFromDigestBytes(rpId)),
				LinkSpecifier.ed25519Id(rpEd));

		final byte[] body = processor.buildIntroduce1Body(kex, cookie, rpOnionKey, rpSpecs);
		assertTrue("body fits a relay cell", body.length <= 498);
		assertTrue("body is padded to at least the C tor minimum plus CLIENT_PK and MAC", body.length >= HSV3IntroductionProcessor.INTRODUCE1_MIN_SIZE + 64);

		/* --- service side decode --- */
		final ByteBuffer bb = ByteBuffer.wrap(body);
		final byte[] legacyKeyId = new byte[20];
		bb.get(legacyKeyId);
		assertArrayEquals(new byte[20], legacyKeyId);
		assertEquals(2, bb.get() & 0xFF);          // AUTH_KEY_TYPE ed25519
		assertEquals(32, bb.getShort() & 0xFFFF);   // AUTH_KEY_LEN
		final byte[] authKey = new byte[32];
		bb.get(authKey);
		assertArrayEquals(ipData.authKey.publicKey, authKey);
		assertEquals(0, bb.get() & 0xFF);           // N_EXTENSIONS
		final int headerLen = bb.position();
		final byte[] clientPk = new byte[32];
		bb.get(clientPk);
		assertArrayEquals(kex.getClientPublicKey(), clientPk);
		final byte[] encryptedData = new byte[bb.remaining() - 32];
		bb.get(encryptedData);
		final byte[] mac = new byte[32];
		bb.get(mac);

		/* intro_secret_hs_input = EXP(X,b) | AUTH_KEY | X | B | PROTOID */
		final byte[] expXb = new byte[32];
		Curve25519.crypto_scalarmult(expXb, ipData.encKeyPrivate, clientPk);
		final byte[] secretInput = HSNtorKeyAgreement.concat(expXb, authKey, clientPk, ipData.encKeyPublic, HSNtorKeyAgreement.PROTOID.getBytes("ISO-8859-1"));
		final byte[] info = HSNtorKeyAgreement.concat((HSNtorKeyAgreement.PROTOID + ":hs_key_expand").getBytes("ISO-8859-1"), svc.subcredential);
		final byte[] keys = Keccak.shake256(64, secretInput, (HSNtorKeyAgreement.PROTOID + ":hs_key_extract").getBytes("ISO-8859-1"), info);
		final byte[] encKey = Arrays.copyOfRange(keys, 0, 32);
		final byte[] macKey = Arrays.copyOfRange(keys, 32, 64);

		/* MAC covers header | CLIENT_PK | ENCRYPTED_DATA */
		final byte[] macInput = Arrays.copyOf(body, headerLen + 32 + encryptedData.length);
		final byte[] expectedMac = Keccak.digestSha3_256(HSNtorKeyAgreement.int8(32), macKey, macInput);
		assertArrayEquals(expectedMac, mac);

		/* Decrypt with AES-256-CTR, zero IV (JDK cipher as an independent oracle) */
		final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
		c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(new byte[16]));
		final ByteBuffer plain = ByteBuffer.wrap(c.doFinal(encryptedData));
		final byte[] gotCookie = new byte[20];
		plain.get(gotCookie);
		assertArrayEquals(cookie, gotCookie);
		assertEquals(0, plain.get() & 0xFF);         // N_EXTENSIONS
		assertEquals(1, plain.get() & 0xFF);         // ONION_KEY_TYPE ntor
		assertEquals(32, plain.getShort() & 0xFFFF); // ONION_KEY_LEN
		final byte[] gotOnionKey = new byte[32];
		plain.get(gotOnionKey);
		assertArrayEquals(rpOnionKey, gotOnionKey);
		final List<LinkSpecifier> gotSpecs = LinkSpecifier.parseList(plain);
		assertEquals(rpSpecs, gotSpecs);
		assertEquals(IPv4Address.createFromString("10.1.2.3"), gotSpecs.get(0).getIPv4Address());
		assertEquals(9001, gotSpecs.get(0).getPort());
		/* remaining bytes are zero padding */
		while(plain.hasRemaining()) {
			assertEquals(0, plain.get());
		}
	}

	@Test
	public void testLinkSpecifierEncoding() {
		final List<LinkSpecifier> specs = Arrays.asList(
				LinkSpecifier.ipv4(IPv4Address.createFromString("192.0.2.1"), 443),
				new LinkSpecifier(99, new byte[] { 1, 2, 3 }));
		final byte[] enc = LinkSpecifier.encodeList(specs);
		assertEquals(1 + 2 + 6 + 2 + 3, enc.length);
		assertEquals(2, enc[0]);
		assertEquals(0, enc[1]);
		assertEquals(6, enc[2]);
		assertEquals((byte) 192, enc[3]);
		assertEquals(1, enc[7]);
		assertEquals((byte) 0xBB, enc[8]);
		assertEquals(specs, LinkSpecifier.parseList(enc));
	}
}
