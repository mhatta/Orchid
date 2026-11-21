package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DormantListener;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;

/**
 * What the circuit manager does when Orchid becomes dormant and wakes up.
 */
public class CircuitDormancyTest {
	private final List<Boolean> cacheDormant = Collections.synchronizedList(new ArrayList<Boolean>());
	private CircuitManagerImpl manager;

	/* An object of the interface whose methods return null, false or 0. */
	@SuppressWarnings("unchecked")
	private static <T> T nothing(Class<T> type, final InvocationHandler extra) {
		return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, new InvocationHandler() {
			public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
				if(extra != null) {
					extra.invoke(proxy, method, args);
				}
				final Class<?> r = method.getReturnType();
				if(r == boolean.class) return false;
				if(r == int.class) return 0;
				if(r == long.class) return 0L;
				if(r == List.class) return Collections.emptyList();
				return null;
			}
		});
	}

	private CircuitManagerImpl manager(TorConfig config, DirectoryDownloaderImpl downloader) {
		final Directory directory = nothing(Directory.class, null);
		final ConnectionCache cache = nothing(ConnectionCache.class, new InvocationHandler() {
			public Object invoke(Object proxy, Method method, Object[] args) {
				if(method.getName().equals("setDormant")) {
					cacheDormant.add((Boolean) args[0]);
				}
				return null;
			}
		});
		manager = new CircuitManagerImpl(config, downloader, directory, cache, null);
		return manager;
	}

	@After
	public void after() {
		if(manager != null) {
			manager.stopBuildingCircuits(true);
		}
	}

	@Test(timeout = 20000)
	public void testDormancyStopsAndWakingRestarts() {
		final TorConfig config = new TorConfigImpl();
		config.setUseEntryGuards(false);
		final DirectoryDownloaderImpl downloader = new DirectoryDownloaderImpl(config, null);
		final CircuitManagerImpl cm = manager(config, downloader);
		final List<Boolean> events = Collections.synchronizedList(new ArrayList<Boolean>());
		cm.addDormantListener(new DormantListener() {
			public void dormantStateChanged(boolean dormant) {
				events.add(dormant);
			}
		});
		cm.startBuildingCircuits();
		assertFalse(cm.isDormant());

		cm.setDormant(true);
		assertTrue(cm.isDormant());
		assertTrue(downloader.isDormant());
		assertEquals("[true]", cacheDormant.toString());

		cm.setDormant(false);
		assertFalse(cm.isDormant());
		assertFalse(downloader.isDormant());
		assertEquals("[true, false]", cacheDormant.toString());
		assertEquals("[true, false]", events.toString());
	}

	@Test(timeout = 20000)
	public void testStreamRequestWakesUp() throws Exception {
		final TorConfig config = new TorConfigImpl();
		config.setUseEntryGuards(false);
		final CircuitManagerImpl cm = manager(config, new DirectoryDownloaderImpl(config, null));
		cm.startBuildingCircuits();
		cm.setDormant(true);
		final Thread request = new Thread(new Runnable() {
			public void run() {
				try {
					cm.openExitStreamTo("example.com", 443);
				} catch(Exception e) {
					// Interrupted below: there are no relays.
				}
			}
		});
		request.start();
		final long deadline = System.currentTimeMillis() + 5000;
		while(cm.isDormant() && System.currentTimeMillis() < deadline) {
			Thread.sleep(10);
		}
		assertFalse(cm.isDormant());
		request.interrupt();
		request.join(5000);
	}

	@Test
	public void testNoOpenClientStreamsWithoutCircuits() {
		final TorConfig config = new TorConfigImpl();
		config.setUseEntryGuards(false);
		final CircuitManagerImpl cm = manager(config, new DirectoryDownloaderImpl(config, null));
		assertFalse(cm.hasOpenClientStreams());
		// No circuits to retire, no exception.
		cm.setDormant(true);
		assertTrue(cm.isDormant());
	}

	@Test
	public void testUnusedLifetimeFollowsCircuitIdleTimeout() {
		final TorConfig config = new TorConfigImpl();
		config.setUseEntryGuards(false);
		config.setCircuitIdleTimeout(10, java.util.concurrent.TimeUnit.MINUTES);
		final CircuitManagerImpl cm = manager(config, new DirectoryDownloaderImpl(config, null));
		for(int i = 0; i < 50; i++) {
			final long lifetime = new ExitCircuitImpl(cm, (Router) null).getUnusedLifetime();
			assertTrue(lifetime >= 5 * 60 * 1000);
			assertTrue(lifetime < 10 * 60 * 1000);
		}
		// A timeout too short to halve still gives a positive lifetime.
		assertTrue(CircuitImpl.chooseUnusedLifetime(1) >= 1);
		assertTrue(CircuitImpl.chooseUnusedLifetime(0) >= 1);
	}

	@Test
	public void testUnusedLifetimeIsBetween30And60Minutes() {
		for(int i = 0; i < 50; i++) {
			final ExitCircuitImpl c = new ExitCircuitImpl(null, (Router) null);
			assertTrue(c.getUnusedLifetime() >= 30 * 60 * 1000);
			assertTrue(c.getUnusedLifetime() < 60 * 60 * 1000);
			// Not built: never "unused too long".
			assertFalse(c.isUnusedTooLong());
		}
	}
}
