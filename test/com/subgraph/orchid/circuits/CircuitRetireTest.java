package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

import org.junit.Test;

import com.subgraph.orchid.Router;

/**
 * Circuits retired by a new identity (CircuitManagerImpl#newIdentity()) take
 * no new streams, including circuits that were still being built.
 */
public class CircuitRetireTest {
	private final Object lock = new Object();

	private static ExitCircuitImpl circuit() {
		final Router exit = (Router) Proxy.newProxyInstance(Router.class.getClassLoader(),
				new Class<?>[] { Router.class }, new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) {
						if(m.getName().equals("exitPolicyAccepts")) {
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
		return new ExitCircuitImpl(null, exit);
	}

	private StreamExitRequest request() {
		return new StreamExitRequest(lock, "example.com", 443, null);
	}

	@Test
	public void testCircuitTakesStreamsUntilRetired() {
		final ExitCircuitImpl c = circuit();
		assertFalse(c.isMarkedForClose());
		assertTrue(c.canHandleExitTo(request()));
	}

	@Test
	public void testCircuitRetiredWhileBuildingTakesNoStreams() {
		final ExitCircuitImpl c = circuit();
		c.retire();
		assertTrue(c.isMarkedForClose());
		assertFalse(c.canHandleExitTo(request()));
		// The build completing later does not make it usable again.
		c.notifyCircuitBuildCompleted();
		assertTrue(c.isMarkedForClose());
		assertFalse(c.canHandleExitTo(request()));
	}
}
