package com.subgraph.orchid.crypto;

import java.util.Arrays;

/**
 * A compact, dependency-free implementation of the Keccak-f[1600] sponge
 * construction (FIPS 202), providing SHA3-256 and SHAKE256.
 *
 * The v3 onion service protocol (rend-spec-v3) uses SHA3-256 as its hash and
 * MAC primitive and SHAKE256 as its KDF.  Neither is guaranteed to be
 * available through the JCA on every runtime Orchid targets (Java 8 and
 * older Android releases have no SHA3 provider, and no mainstream JDK exposes
 * SHAKE256 as a MessageDigest), so a pure Java implementation is used.
 *
 * Instances are not thread safe.  The running state can be copied with
 * {@link #copy()} which is needed for the per-hop "peek digest" check done on
 * incoming relay cells.
 */
public final class Keccak {

	public static final int SHA3_256_DIGEST_LEN = 32;

	private static final int STATE_WORDS = 25;
	private static final byte SHA3_SUFFIX = 0x06;
	private static final byte SHAKE_SUFFIX = 0x1F;

	private static final long[] RC = {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
		0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
		0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
		0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
		0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
		0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};

	private static final int[] ROT = {
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
	};

	private final long[] state = new long[STATE_WORDS];
	private final int rateBytes;
	private final byte suffix;
	private final int fixedOutputLen;
	private final byte[] block;
	private int blockPos;
	private boolean squeezing;
	private int squeezePos;

	private Keccak(int rateBytes, byte suffix, int fixedOutputLen) {
		this.rateBytes = rateBytes;
		this.suffix = suffix;
		this.fixedOutputLen = fixedOutputLen;
		this.block = new byte[rateBytes];
	}

	/** Create a new SHA3-256 instance. */
	public static Keccak sha3_256() {
		return new Keccak(136, SHA3_SUFFIX, SHA3_256_DIGEST_LEN);
	}

	/** Create a new SHAKE256 (extendable output) instance. */
	public static Keccak shake256() {
		return new Keccak(136, SHAKE_SUFFIX, 0);
	}

	/** Convenience: SHA3-256 of the concatenation of the given byte arrays. */
	public static byte[] digestSha3_256(byte[]... inputs) {
		final Keccak k = sha3_256();
		for(byte[] in: inputs) {
			k.update(in);
		}
		return k.digest();
	}

	/** Convenience: SHAKE256 of the concatenation of the given byte arrays, squeezing <code>outputLen</code> bytes. */
	public static byte[] shake256(int outputLen, byte[]... inputs) {
		final Keccak k = shake256();
		for(byte[] in: inputs) {
			k.update(in);
		}
		return k.squeeze(outputLen);
	}

	public Keccak update(byte[] data) {
		return update(data, 0, data.length);
	}

	public Keccak update(byte[] data, int offset, int length) {
		if(squeezing) {
			throw new IllegalStateException("Cannot absorb after squeezing has started");
		}
		int i = offset;
		final int end = offset + length;
		while(i < end) {
			final int n = Math.min(rateBytes - blockPos, end - i);
			System.arraycopy(data, i, block, blockPos, n);
			blockPos += n;
			i += n;
			if(blockPos == rateBytes) {
				absorbBlock();
				blockPos = 0;
			}
		}
		return this;
	}

	/** Return the SHA3-256 digest.  Only valid for instances created with {@link #sha3_256()}. */
	public byte[] digest() {
		if(fixedOutputLen == 0) {
			throw new IllegalStateException("digest() is only valid for fixed length instances; use squeeze()");
		}
		return squeeze(fixedOutputLen);
	}

	/**
	 * Squeeze <code>outputLen</code> bytes from the sponge.  The first call pads and
	 * permutes; subsequent calls continue the output stream (XOF semantics).
	 */
	public byte[] squeeze(int outputLen) {
		final byte[] out = new byte[outputLen];
		squeeze(out, 0, outputLen);
		return out;
	}

	public void squeeze(byte[] out, int offset, int length) {
		if(!squeezing) {
			pad();
			squeezing = true;
			squeezePos = 0;
		}
		int i = offset;
		final int end = offset + length;
		while(i < end) {
			if(squeezePos == rateBytes) {
				permute(state);
				squeezePos = 0;
			}
			final int n = Math.min(rateBytes - squeezePos, end - i);
			for(int j = 0; j < n; j++) {
				final int idx = squeezePos + j;
				out[i + j] = (byte) (state[idx >>> 3] >>> (8 * (idx & 7)));
			}
			squeezePos += n;
			i += n;
		}
	}

	/** Return a copy of this instance with the same internal state. */
	public Keccak copy() {
		final Keccak k = new Keccak(rateBytes, suffix, fixedOutputLen);
		System.arraycopy(state, 0, k.state, 0, STATE_WORDS);
		System.arraycopy(block, 0, k.block, 0, rateBytes);
		k.blockPos = blockPos;
		k.squeezing = squeezing;
		k.squeezePos = squeezePos;
		return k;
	}

	private void pad() {
		Arrays.fill(block, blockPos, rateBytes, (byte) 0);
		block[blockPos] ^= suffix;
		block[rateBytes - 1] ^= (byte) 0x80;
		absorbBlock();
		blockPos = 0;
	}

	private void absorbBlock() {
		for(int i = 0; i < rateBytes / 8; i++) {
			long w = 0;
			for(int j = 7; j >= 0; j--) {
				w = (w << 8) | (block[i * 8 + j] & 0xFFL);
			}
			state[i] ^= w;
		}
		permute(state);
	}

	private static void permute(long[] a) {
		final long[] c = new long[5];
		final long[] b = new long[25];
		for(int round = 0; round < 24; round++) {
			// theta
			for(int x = 0; x < 5; x++) {
				c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
			}
			for(int x = 0; x < 5; x++) {
				final long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
				for(int y = 0; y < 25; y += 5) {
					a[y + x] ^= d;
				}
			}
			// rho and pi
			for(int x = 0; x < 5; x++) {
				for(int y = 0; y < 5; y++) {
					final int from = x + 5 * y;
					final int to = y + 5 * ((2 * x + 3 * y) % 5);
					b[to] = Long.rotateLeft(a[from], ROT[from]);
				}
			}
			// chi
			for(int y = 0; y < 25; y += 5) {
				for(int x = 0; x < 5; x++) {
					a[y + x] = b[y + x] ^ ((~b[y + (x + 1) % 5]) & b[y + (x + 2) % 5]);
				}
			}
			// iota
			a[0] ^= RC[round];
		}
	}
}
