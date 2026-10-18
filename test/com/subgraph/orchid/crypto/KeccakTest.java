package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import com.subgraph.orchid.encoders.Hex;

public class KeccakTest {

	static String hex(byte[] b) {
		return new String(Hex.encode(b));
	}

	@Test
	public void testSha3_256KnownVectors() {
		assertEquals("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", hex(Keccak.digestSha3_256(new byte[0])));
		/* Vector used by tor's hs_build_address.py to detect the final SHA3 padding */
		assertEquals("e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51", hex(Keccak.digestSha3_256("Hello World".getBytes())));
		assertEquals("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", hex(Keccak.digestSha3_256("abc".getBytes())));
	}

	@Test
	public void testShake256KnownVectors() {
		assertEquals("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f", hex(Keccak.shake256(32, new byte[0])));
		assertEquals("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739", hex(Keccak.shake256(32, "abc".getBytes())));
	}

	@Test
	public void testSha3_256AgainstJdkWhenAvailable() throws Exception {
		MessageDigest jdk;
		try {
			jdk = MessageDigest.getInstance("SHA3-256");
		} catch (Exception e) {
			return; // No SHA3 provider on this runtime (Java 8); known vectors above still cover us.
		}
		final Random r = new Random(42);
		for(int n = 0; n < 700; n += 13) {
			final byte[] m = new byte[n];
			r.nextBytes(m);
			final Keccak k = Keccak.sha3_256();
			int pos = 0;
			while(pos < n) {
				final int c = Math.min(n - pos, 1 + r.nextInt(60));
				k.update(m, pos, c);
				pos += c;
			}
			assertArrayEquals("length "+ n, jdk.digest(m), k.digest());
		}
	}

	@Test
	public void testCopyPreservesState() {
		final Keccak a = Keccak.sha3_256().update("abc".getBytes());
		final Keccak b = a.copy();
		b.update("def".getBytes());
		assertEquals(hex(Keccak.digestSha3_256("abc".getBytes())), hex(a.digest()));
		assertEquals(hex(Keccak.digestSha3_256("abcdef".getBytes())), hex(b.digest()));
	}

	@Test
	public void testShakeStreamingSqueeze() {
		final Keccak k = Keccak.shake256().update("xyz".getBytes());
		final byte[] p1 = k.squeeze(100);
		final byte[] p2 = k.squeeze(300);
		final byte[] all = Keccak.shake256(400, "xyz".getBytes());
		assertArrayEquals(Arrays.copyOf(all, 100), p1);
		assertArrayEquals(Arrays.copyOfRange(all, 100, 400), p2);
	}

	@Test
	public void testTorMessageDigestSha3Mode() {
		final TorMessageDigest d = TorMessageDigest.createSha3_256();
		d.update("Hello ".getBytes());
		final byte[] peek = d.peekDigest("World".getBytes(), 0, 5);
		assertEquals("e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51", hex(peek));
		d.update("World".getBytes());
		assertEquals("e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51", hex(d.getDigestBytes()));
		// getDigestBytes() must not disturb the running state
		assertEquals("e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51", hex(d.getDigestBytes()));
	}
}
