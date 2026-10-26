package com.subgraph.orchid.crypto;

import java.security.SecureRandom;

public class TorRandom {

	private final SecureRandom random;
	
	public TorRandom() {
		random = createRandom();
	}
	
	/*
	 * The platform's default generator (NativePRNG or DRBG on the JDK,
	 * Conscrypt's on Android), seeded from the operating system.  Orchid
	 * asked for "SHA1PRNG" by name before: a legacy algorithm whose
	 * implementation and seeding differ between providers, and whose flawed
	 * seeding on early Android releases exposed private keys in other
	 * applications.
	 */
	private static SecureRandom createRandom() {
		return new SecureRandom();
	}

	/** The name of the underlying algorithm, for tests and diagnostics. */
	String getAlgorithm() {
		return random.getAlgorithm();
	}

	public byte[] getBytes(int n) {
		final byte[] bs = new byte[n];
		random.nextBytes(bs);
		return bs;
	}

	public long nextLong(long n) {
		long bits, val;
		do {
			bits = nextLong();
			val = bits % n;
		} while(bits - val + (n - 1) < 0);
		return val;
	}

	public int nextInt(int n) {
		return random.nextInt(n);
	}
	
	public int nextInt() {
		return random.nextInt() & Integer.MAX_VALUE;
	}
	
	/**
	 * Return a uniformly distributed positive random value between 0 and Long.MAX_VALUE
	 * 
	 * @return A positive random value between 0 and Long.MAX_VALUE.
	 */
	public long nextLong() {
		return random.nextLong() & Long.MAX_VALUE;
	}

}
