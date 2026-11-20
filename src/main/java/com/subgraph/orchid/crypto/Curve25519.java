package com.subgraph.orchid.crypto;

/**
 * X25519 (RFC 7748) in the calling convention of NaCl's crypto_scalarmult,
 * which Orchid has used since it took this class from jnacl.
 *
 * <p>Since 2.7.0 the arithmetic is {@link X25519}, derived from Bouncy
 * Castle: a Montgomery ladder with constant-time conditional swaps and no
 * secret-dependent branches or array indices.  The earlier code, a port
 * of the NaCl reference implementation, selected with arithmetic too, but
 * had never been checked against the RFC 7748 test vectors, and it did
 * not clear the top bit of the peer's u-coordinate as RFC 7748 requires.
 * Both points are covered by Curve25519Test.
 */
public class Curve25519 {
	public static final int KEY_LENGTH = 32;

	/**
	 * q = X25519(n, 9): the public key of the private key n.  n is clamped
	 * as RFC 7748 says; its bytes are not changed.
	 *
	 * @return 0, as NaCl's function does.
	 */
	public static int crypto_scalarmult_base(byte[] q, byte[] n) {
		checkLengths(q, n);
		X25519.scalarMultBase(n, 0, q, 0);
		return 0;
	}

	/**
	 * q = X25519(n, p): the shared secret of private key n and public key p.
	 * n is clamped and the top bit of p is ignored, as RFC 7748 says.  The
	 * caller checks for an all-zero result (a low-order p).
	 *
	 * @return 0, as NaCl's function does.
	 */
	public static int crypto_scalarmult(byte[] q, byte[] n, byte[] p) {
		checkLengths(q, n);
		if(p == null || p.length < KEY_LENGTH) {
			throw new IllegalArgumentException("X25519 public key must be "+ KEY_LENGTH +" bytes");
		}
		X25519.scalarMult(n, 0, p, 0, q, 0);
		return 0;
	}

	private static void checkLengths(byte[] q, byte[] n) {
		if(q == null || q.length < KEY_LENGTH) {
			throw new IllegalArgumentException("X25519 output must be "+ KEY_LENGTH +" bytes");
		}
		if(n == null || n.length < KEY_LENGTH) {
			throw new IllegalArgumentException("X25519 private key must be "+ KEY_LENGTH +" bytes");
		}
	}
}
