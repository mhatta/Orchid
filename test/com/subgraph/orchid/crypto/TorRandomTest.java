package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

public class TorRandomTest {
	@Test
	public void testUsesThePlatformDefaultGenerator() {
		final TorRandom r = new TorRandom();
		assertFalse("SHA1PRNG".equals(r.getAlgorithm()));
		assertEquals(new java.security.SecureRandom().getAlgorithm(), r.getAlgorithm());
	}

	@Test
	public void testOutput() {
		final TorRandom r = new TorRandom();
		assertEquals(32, r.getBytes(32).length);
		assertNotEquals(Arrays.toString(r.getBytes(32)), Arrays.toString(r.getBytes(32)));
		for(int i = 0; i < 1000; i++) {
			final int v = r.nextInt(10);
			assertTrue(v >= 0 && v < 10);
			final long l = r.nextLong(1000);
			assertTrue(l >= 0 && l < 1000);
		}
	}
}
