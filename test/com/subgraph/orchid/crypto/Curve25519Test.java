package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.encoders.Hex;

/** X25519 against the test vectors of RFC 7748, sections 5.2 and 6.1. */
public class Curve25519Test {

	private static byte[] x25519(String k, String u) {
		final byte[] out = new byte[32];
		Curve25519.crypto_scalarmult(out, Hex.decode(k), Hex.decode(u));
		return out;
	}

	@Test
	public void rfc7748Vector1() {
		// The u-coordinate has its top bit set: it must be ignored.
		assertArrayEquals(Hex.decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
				x25519("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
						"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
	}

	@Test
	public void rfc7748Vector2() {
		assertArrayEquals(Hex.decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
				x25519("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
						"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"));
	}

	/* RFC 7748 5.2: k = u = 9, then k <- X25519(k, u), u <- old k. */
	@Test
	public void rfc7748Iterated() {
		byte[] k = new byte[32];
		byte[] u = new byte[32];
		k[0] = 9;
		u[0] = 9;
		for(int i = 1; i <= 1000; i++) {
			final byte[] r = new byte[32];
			Curve25519.crypto_scalarmult(r, k, u);
			u = k;
			k = r;
			if(i == 1) {
				assertArrayEquals(Hex.decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), k);
			}
		}
		assertArrayEquals(Hex.decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), k);
	}

	/* RFC 7748 6.1: Diffie-Hellman. */
	@Test
	public void rfc7748DiffieHellman() {
		final byte[] alice = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
		final byte[] bob = Hex.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
		final byte[] alicePub = new byte[32];
		final byte[] bobPub = new byte[32];
		Curve25519.crypto_scalarmult_base(alicePub, alice);
		Curve25519.crypto_scalarmult_base(bobPub, bob);
		assertArrayEquals(Hex.decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), alicePub);
		assertArrayEquals(Hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), bobPub);
		final byte[] k1 = new byte[32];
		final byte[] k2 = new byte[32];
		Curve25519.crypto_scalarmult(k1, alice, bobPub);
		Curve25519.crypto_scalarmult(k2, bob, alicePub);
		final byte[] shared = Hex.decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
		assertArrayEquals(shared, k1);
		assertArrayEquals(shared, k2);
	}

	/* Low-order points give the all-zero output the callers reject. */
	@Test
	public void lowOrderPointsGiveZero() {
		final String k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
		for(String u: new String[] {
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0100000000000000000000000000000000000000000000000000000000000000" }) {
			assertArrayEquals(new byte[32], x25519(k, u));
		}
	}

	/* The private key is clamped on a copy, as before. */
	@Test
	public void privateKeyIsNotChanged() {
		final byte[] k = new byte[32];
		Arrays.fill(k, (byte) 0xff);
		final byte[] copy = k.clone();
		Curve25519.crypto_scalarmult_base(new byte[32], k);
		assertArrayEquals(copy, k);
		assertEquals(32, k.length);
	}
}
