package com.subgraph.orchid.circuits.guards;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.HexDigest;

public class VanguardsLiteTest {
	private static final long HOUR = 60 * 60 * 1000L;
	private static final long DAY = 24 * HOUR;

	private FakeNetwork net;
	private VanguardsLite vanguards;

	@Before
	public void setUp() {
		net = new FakeNetwork(10, 40);
		final TorConfig config = new TorConfigImpl();
		vanguards = new VanguardsLite(config, net.directory, new CircuitNodeChooser(config, net.directory), net.clock());
	}

	@Test
	public void fourLayer2GuardsAreKept() {
		final Set<Router> chosen = new HashSet<Router>();
		for(int i = 0; i < 200; i++) {
			chosen.add(vanguards.chooseLayer2(FakeNetwork.none()));
		}
		assertEquals(4, vanguards.getLayer2Identities().size());
		assertEquals(4, chosen.size());
		for(Router r: chosen) {
			assertTrue(vanguards.getLayer2Identities().contains(r.getIdentityHash()));
		}
	}

	@Test
	public void excludedRoutersAreNotChosen() {
		vanguards.chooseLayer2(FakeNetwork.none());
		final List<HexDigest> ids = vanguards.getLayer2Identities();
		final Set<Router> excluded = new HashSet<Router>();
		for(int i = 0; i < 3; i++) {
			excluded.add(net.directory.getRouterByIdentity(ids.get(i)));
		}
		final Router last = net.directory.getRouterByIdentity(ids.get(3));
		for(int i = 0; i < 20; i++) {
			assertEquals(last, vanguards.chooseLayer2(excluded));
		}
		excluded.add(last);
		assertNull(vanguards.chooseLayer2(excluded));
	}

	@Test
	public void layer2GuardsRotate() {
		vanguards.chooseLayer2(FakeNetwork.none());
		final List<HexDigest> before = new ArrayList<HexDigest>(vanguards.getLayer2Identities());
		net.time.addAndGet(23 * HOUR);
		vanguards.chooseLayer2(FakeNetwork.none());
		assertEquals(before, vanguards.getLayer2Identities());
		net.time.addAndGet(12 * DAY);
		assertNotNull(vanguards.chooseLayer2(FakeNetwork.none()));
		final List<HexDigest> after = vanguards.getLayer2Identities();
		assertEquals(4, after.size());
		final Set<HexDigest> kept = new HashSet<HexDigest>(before);
		kept.retainAll(after);
		/* Every old entry expired; a new one may happen to be the same relay. */
		assertTrue(kept.size() < 4);
	}

	@Test
	public void downRelayIsReplaced() {
		vanguards.chooseLayer2(FakeNetwork.none());
		final HexDigest gone = vanguards.getLayer2Identities().get(0);
		net.relay(net.directory.getRouterByIdentity(gone)).running = false;
		vanguards.chooseLayer2(FakeNetwork.none());
		assertFalse(vanguards.getLayer2Identities().contains(gone));
		assertEquals(4, vanguards.getLayer2Identities().size());
	}
}
