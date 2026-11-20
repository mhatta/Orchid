package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.Router;

/**
 * When all isolation groups are in use, the idle group is closed to make
 * room (IsolateDestAddr makes every host a group).
 */
public class IsolationGroupReclaimTest {
	private final Object lock = new Object();

	private static ExitCircuitImpl claimed(String key) {
		final Router exit = (Router) Proxy.newProxyInstance(Router.class.getClassLoader(),
				new Class<?>[] { Router.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						if(m.getName().equals("exitPolicyAccepts") || m.getReturnType() == boolean.class) {
							return m.getName().equals("exitPolicyAccepts");
						}
						return m.getReturnType() == int.class ? Integer.valueOf(0) : null;
					}
				});
		final ExitCircuitImpl c = new ExitCircuitImpl(null, exit);
		c.claimIsolation(key);
		return c;
	}

	private StreamExitRequest waiting(String key) {
		return new StreamExitRequest(lock, "example.com", 443, key);
	}

	@Test
	public void testIdleGroupIsChosen() {
		final ExitCircuitImpl a = claimed("dest=a");
		final ExitCircuitImpl b = claimed("dest=b");
		final List<ExitCircuitImpl> victims = CircuitManagerImpl.chooseIdleIsolationGroup(
				Arrays.asList(a, b), Arrays.asList(waiting("dest=b")), "dest=c");
		assertEquals(1, victims.size());
		assertSame("the group with a waiting stream is kept", a, victims.get(0));
	}

	@Test
	public void testWantedAndUnclaimedAreKept() {
		final ExitCircuitImpl wanted = claimed("dest=c");
		final ExitCircuitImpl shared = claimed(null);
		assertTrue(CircuitManagerImpl.chooseIdleIsolationGroup(Arrays.asList(wanted, shared),
				Collections.<StreamExitRequest>emptyList(), "dest=c").isEmpty());
	}

	@Test
	public void testAllCircuitsOfTheGroupAreClosed() {
		final ExitCircuitImpl a1 = claimed("dest=a");
		final ExitCircuitImpl a2 = claimed("dest=a");
		final List<ExitCircuitImpl> victims = CircuitManagerImpl.chooseIdleIsolationGroup(
				Arrays.asList(a1, a2), Collections.<StreamExitRequest>emptyList(), "dest=c");
		assertEquals(2, victims.size());
	}

	@Test
	public void testRetiredCircuitsAreIgnored() {
		final ExitCircuitImpl a = claimed("dest=a");
		a.retire();
		assertTrue(CircuitManagerImpl.chooseIdleIsolationGroup(Arrays.asList(a),
				Collections.<StreamExitRequest>emptyList(), "dest=c").isEmpty());
	}
}
