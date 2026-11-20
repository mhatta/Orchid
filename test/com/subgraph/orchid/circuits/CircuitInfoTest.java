package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.junit.Test;

import com.subgraph.orchid.CircuitInfo;
import com.subgraph.orchid.RelayInfo;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.data.HexDigest;

/** The circuit snapshots of TorClient#getCircuits(). */
public class CircuitInfoTest {

	private static Router router(final String nickname, final String country) {
		return (Router) Proxy.newProxyInstance(Router.class.getClassLoader(),
				new Class<?>[] { Router.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						final String n = m.getName();
						if(n.equals("getIdentityHash")) {
							final byte[] b = new byte[20];
							b[0] = (byte) 0xab;
							return HexDigest.createFromDigestBytes(b);
						} else if(n.equals("getNickname")) {
							return nickname;
						} else if(n.equals("getCountryCode")) {
							return country;
						} else if(n.equals("exitPolicyAccepts")) {
							return true;
						}
						if(m.getReturnType() == boolean.class) {
							return false;
						}
						if(m.getReturnType() == int.class) {
							return 0;
						}
						return null;
					}
				});
	}

	@Test
	public void testExitCircuitStates() {
		final ExitCircuitImpl c = new ExitCircuitImpl(null, router("exit", "DE"));
		CircuitInfo info = c.getInfo();
		assertEquals(CircuitInfo.Purpose.EXIT, info.getPurpose());
		assertEquals(CircuitInfo.State.BUILDING, info.getState());
		assertEquals(0, info.getStreamCount());
		assertTrue(info.getPath().isEmpty());
		assertFalse(info.isIsolated());

		c.notifyCircuitBuildCompleted();
		assertEquals(CircuitInfo.State.OPEN, c.getInfo().getState());
	}

	@Test
	public void testRetiredBeforeBuiltIsClosing() {
		final ExitCircuitImpl c = new ExitCircuitImpl(null, router("exit", "DE"));
		c.retire();
		c.notifyCircuitBuildCompleted();
		assertEquals(CircuitInfo.State.CLOSING, c.getInfo().getState());
	}

	@Test
	public void testIsolationIsShownButNotTheKey() {
		final ExitCircuitImpl isolated = new ExitCircuitImpl(null, router("exit", "DE"));
		isolated.claimIsolation("socks5:616c696365:736563726574");
		assertTrue(isolated.getInfo().isIsolated());
		assertFalse(isolated.getInfo().toString().contains("616c696365"));
		final ExitCircuitImpl shared = new ExitCircuitImpl(null, router("exit", "DE"));
		shared.claimIsolation(null);
		assertFalse(shared.getInfo().isIsolated());
	}

	@Test
	public void testInternalCircuitPurpose() {
		assertEquals(CircuitInfo.Purpose.INTERNAL, new InternalCircuitImpl(null, null).getInfo().getPurpose());
	}

	@Test
	public void testRelayInfo() {
		final RelayInfo r = CircuitImpl.relayInfo(router("relay1", "JP"));
		assertEquals("AB00000000000000000000000000000000000000", r.getFingerprint());
		assertEquals("relay1", r.getNickname());
		assertEquals("JP", r.getCountryCode());
		assertNull("unknown country", CircuitImpl.relayInfo(router("relay2", "??")).getCountryCode());
	}

	/* Logging the snapshots must not record which relays were used. */
	@Test
	public void testToStringLeavesOutTheRelays() {
		final RelayInfo r = CircuitImpl.relayInfo(router("relay1", "JP"));
		assertFalse(r.toString().contains("relay1"));
		assertFalse(r.toString().toUpperCase().contains("AB000000"));
		final CircuitInfo c = new CircuitInfo(CircuitInfo.Purpose.EXIT, CircuitInfo.State.OPEN,
				java.util.Arrays.asList(r, r, r), 2, true, 5);
		assertFalse(c.toString().contains("relay1"));
		assertFalse(c.toString().toUpperCase().contains("AB000000"));
		final com.subgraph.orchid.GuardInfo g = new com.subgraph.orchid.GuardInfo(r, true, true, true,
				com.subgraph.orchid.GuardInfo.Reachability.REACHABLE, new java.util.Date(), null);
		assertFalse(g.toString().contains("relay1"));
		assertFalse(g.toString().toUpperCase().contains("AB000000"));
	}
}
