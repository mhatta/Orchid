package com.subgraph.orchid.circuits.hs;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.data.IPv4Address;

public class HSV3DescriptorParserTest {
	private static final long NOW = System.currentTimeMillis() / 1000;
	private static final long TP = 27000;
	private static final long TP_LEN = 1440;

	private static HSV3DescriptorParser parserFor(HSV3TestServiceEncoder svc, byte[] clientKey) {
		return new HSV3DescriptorParser(svc.blinded.publicKey, svc.subcredential, clientKey, NOW, TP);
	}

	@Test
	public void testParseDescriptorWithoutClientAuth() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(TP, TP_LEN, NOW, 12345);
		final HSV3TestServiceEncoder.IntroPoint ip1 = svc.addIntroPoint(9001);
		final HSV3TestServiceEncoder.IntroPoint ip2 = svc.addIntroPoint(443);
		svc.addIntroPoint(9030);
		final byte[] doc = svc.encodeDescriptor();

		final HSV3Descriptor desc = parserFor(svc, null).parse(doc);
		assertEquals(180, desc.getLifetimeMinutes());
		assertEquals(12345, desc.getRevisionCounter());
		assertFalse(desc.isIntroAuthRequired());
		assertFalse(desc.isSingleOnionService());
		assertTrue(desc.getCreate2Formats().contains(2));
		assertArrayEquals(svc.descriptorSigning.publicKey, desc.getDescriptorSigningKey());
		assertEquals(Ed25519Certificate.CERT_TYPE_HS_DESC_SIGNING, desc.getSigningKeyCert().getCertType());
		assertEquals(3, desc.getIntroductionPoints().size());

		final HSV3IntroductionPoint p1 = desc.getIntroductionPoints().get(0);
		assertArrayEquals(ip1.legacyId, p1.getLegacyIdentity().getRawBytes());
		assertArrayEquals(ip1.ed25519Id, p1.getEd25519Identity());
		assertArrayEquals(ip1.onionKey, p1.getOnionKey());
		assertArrayEquals(ip1.authKey.publicKey, p1.getAuthKey());
		assertArrayEquals(ip1.encKeyPublic, p1.getEncKey());
		assertEquals(9001, p1.getPort());
		int addr = 0;
		for(int i = 0; i < 4; i++) {
			addr = (addr << 8) | (ip1.ipv4[i] & 0xFF);
		}
		assertEquals(new IPv4Address(addr), p1.getIPv4Address());
		assertEquals(443, desc.getIntroductionPoints().get(1).getPort());
		assertArrayEquals(ip2.encKeyPublic, desc.getIntroductionPoints().get(1).getEncKey());
		assertEquals(3, desc.getShuffledIntroductionPoints().size());
		assertFalse(desc.isExpired());
	}

	@Test
	public void testParseDescriptorWithClientAuth() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(TP, TP_LEN, NOW, 7);
		svc.addIntroPoint(80);
		final byte[] clientKey = svc.enableClientAuth();
		final byte[] doc = svc.encodeDescriptor();

		/* With the right key the inner layer decrypts... */
		final HSV3Descriptor desc = parserFor(svc, clientKey).parse(doc);
		assertEquals(1, desc.getIntroductionPoints().size());

		/* ... without a key, or with the wrong key, it does not. */
		try {
			parserFor(svc, null).parse(doc);
			fail("Expected failure without client authorization key");
		} catch (TorParsingException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("MAC"));
		}
		final byte[] wrongKey = clientKey.clone();
		wrongKey[5] ^= 0x10;
		try {
			parserFor(svc, wrongKey).parse(doc);
			fail("Expected failure with wrong client authorization key");
		} catch (TorParsingException e) {
			// expected
		}
	}

	@Test
	public void testRejectsWrongBlindedKey() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(TP, TP_LEN, NOW, 1);
		svc.addIntroPoint(80);
		final byte[] doc = svc.encodeDescriptor();
		/* A client that computed the blinded key for another time period must reject the descriptor. */
		final HSV3TestServiceEncoder other = new HSV3TestServiceEncoder(TP + 1, TP_LEN, NOW, 1);
		try {
			new HSV3DescriptorParser(other.blinded.publicKey, svc.subcredential, null, NOW, TP).parse(doc);
			fail("Expected certificate validation failure");
		} catch (TorParsingException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("certificate"));
		}
	}

	@Test
	public void testRejectsTamperedDocument() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(TP, TP_LEN, NOW, 1);
		svc.addIntroPoint(80);
		final byte[] doc = svc.encodeDescriptor();
		final String text = new String(doc, HSV3TestServiceEncoder.ASCII);
		final byte[] tampered = text.replace("revision-counter 1\n", "revision-counter 2\n").getBytes(HSV3TestServiceEncoder.ASCII);
		assertFalse(Arrays.equals(doc, tampered));
		try {
			parserFor(svc, null).parse(tampered);
			fail("Expected signature failure");
		} catch (TorParsingException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("signature"));
		}
	}

	@Test
	public void testRejectsExpiredCertificates() {
		final HSV3TestServiceEncoder svc = new HSV3TestServiceEncoder(TP, TP_LEN, NOW, 1);
		svc.addIntroPoint(80);
		final byte[] doc = svc.encodeDescriptor();
		/* 55 hours later the 54 hour certificates have expired */
		try {
			new HSV3DescriptorParser(svc.blinded.publicKey, svc.subcredential, null, NOW + 55 * 3600, TP).parse(doc);
			fail("Expected expired certificate failure");
		} catch (TorParsingException e) {
			// expected
		}
	}

	@Test
	public void testDescriptorPathEncoding() {
		final byte[] key = new byte[32];
		Arrays.fill(key, (byte) 0xFF);
		final String path = HSV3DescriptorDownloader.descriptorPath(key);
		assertEquals("/tor/hs/3/", path.substring(0, 10));
		assertEquals(43, path.length() - 10);
		assertFalse(path.endsWith("="));
	}

	@Test
	public void testTokenizer() {
		final String text = "hs-descriptor 3\nfoo bar  baz\nobj\n-----BEGIN MESSAGE-----\nAAAA\nBBBB\n-----END MESSAGE-----\nlast 1\n";
		final java.util.List<HSV3DescriptorParser.Item> items = HSV3DescriptorParser.tokenize(text.getBytes(HSV3TestServiceEncoder.ASCII), 0, text.length());
		assertEquals(4, items.size());
		assertEquals("foo", items.get(1).keyword);
		assertEquals(2, items.get(1).args.size());
		assertEquals("MESSAGE", items.get(2).objectType);
		assertNotNull(items.get(2).objectBytes("MESSAGE"));
		assertEquals(6, items.get(2).objectBytes("MESSAGE").length);
		assertEquals("last", items.get(3).keyword);
	}
}
