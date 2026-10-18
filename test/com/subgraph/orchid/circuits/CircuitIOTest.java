package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class CircuitIOTest {

	/*
	 * A circuit whose build started in the same millisecond (the usual case
	 * when the first hop is reached over a cached connection) must get the
	 * full build timeout, not an immediate timeout.
	 */
	@Test
	public void testZeroElapsedGetsFullTimeout() {
		assertEquals(CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS, CircuitIO.remainingBuildTime(0));
	}

	@Test
	public void testRemainingBuildTime() {
		assertEquals(CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS - 1, CircuitIO.remainingBuildTime(1));
		assertEquals(1000, CircuitIO.remainingBuildTime(CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS - 1000));
		assertEquals(0, CircuitIO.remainingBuildTime(CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS));
		assertEquals(0, CircuitIO.remainingBuildTime(CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS + 5000));
	}

	@Test
	public void testJustStartedCircuitHasTimeToWait() {
		final CircuitStatus status = new CircuitStatus();
		status.updateCreatedTimestamp();
		status.setStateBuilding();
		final long remaining = CircuitIO.remainingBuildTime(status.getMillisecondsElapsedSinceCreated());
		assertTrue("remaining = "+ remaining, remaining > CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS - 1000);
	}
}
