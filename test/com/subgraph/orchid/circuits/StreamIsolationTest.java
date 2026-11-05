package com.subgraph.orchid.circuits;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.subgraph.orchid.Router;

/**
 * A circuit is claimed by the isolation key of the first stream request it
 * serves, and afterwards serves only requests with the same key; requests
 * without a key (null) are a group of their own.
 */
public class StreamIsolationTest {
	private final Object lock = new Object();

	private static ExitCircuitImpl circuit() {
		final Router exit = createNiceMock(Router.class);
		expect(exit.exitPolicyAccepts(443)).andStubReturn(true);
		replay(exit);
		return new ExitCircuitImpl(null, exit);
	}

	private StreamExitRequest request(String key) {
		return new StreamExitRequest(lock, "example.com", 443, key);
	}

	@Test
	public void testFreshCircuitAcceptsAnyKey() {
		final ExitCircuitImpl c = circuit();
		assertTrue(c.canHandleExitTo(request(null)));
		assertTrue(c.canHandleExitTo(request("socks5:61:78")));
	}

	@Test
	public void testClaimedCircuitServesOnlyItsKey() {
		final ExitCircuitImpl c = circuit();
		assertTrue(c.claimIsolation("socks5:61:78"));
		assertTrue(c.canHandleExitTo(request("socks5:61:78")));
		assertTrue(c.claimIsolation("socks5:61:78"));
		assertFalse(c.canHandleExitTo(request("socks5:62:78")));
		assertFalse(c.claimIsolation("socks5:62:78"));
		assertFalse("streams without a key must not join an isolated circuit", c.canHandleExitTo(request(null)));
		assertFalse(c.claimIsolation(null));
	}

	@Test
	public void testCircuitWithoutKeyIsNotUsedForIsolatedStreams() {
		final ExitCircuitImpl c = circuit();
		assertTrue(c.claimIsolation(null));
		assertTrue(c.canHandleExitTo(request(null)));
		assertFalse(c.canHandleExitTo(request("socks5:61:78")));
		assertFalse(c.claimIsolation("socks5:61:78"));
	}

	@Test
	public void testPredictedPortsIgnoreIsolation() {
		// Clean circuits are built for predicted ports before any stream claims them.
		final ExitCircuitImpl c = circuit();
		c.claimIsolation("socks5:61:78");
		assertTrue(c.canHandleExitTo(new PredictedPortTarget(443)));
	}

	@Test
	public void testIsolationKeysInUse() {
		final ExitCircuitImpl a = circuit();
		final ExitCircuitImpl shared = circuit();
		final ExitCircuitImpl fresh = circuit();
		a.claimIsolation("a");
		shared.claimIsolation(null);
		final java.util.Set<String> keys = CircuitManagerImpl.isolationKeysInUse(
				java.util.Arrays.asList(a, shared, fresh),
				java.util.Arrays.asList(request("b"), request(null), request("a")));
		assertEquals(new java.util.HashSet<String>(java.util.Arrays.asList("a", "b")), keys);
	}
}
