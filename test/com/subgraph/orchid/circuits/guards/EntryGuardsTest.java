package com.subgraph.orchid.circuits.guards;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.HexDigest;

public class EntryGuardsTest {
	private static final long MINUTE = 60 * 1000L;
	private static final long DAY = 24 * 60 * MINUTE;

	private FakeNetwork net;
	private TorConfig config;

	@Before
	public void setUp() {
		net = new FakeNetwork(40, 40);
		config = new TorConfigImpl();
	}

	private EntryGuards newGuards() {
		return new EntryGuards(config, net.directory, new CircuitNodeChooser(config, net.directory),
				new Bridges(config, null), net.clock());
	}

	private Router routerOf(SampledGuard g) {
		return net.directory.getRouterByIdentity(g.getIdentity());
	}

	@Test
	public void noGuardWithoutConsensus() throws InterruptedException {
		net.haveConsensus = false;
		final EntryGuards guards = newGuards();
		assertNull(guards.chooseRandomGuard(FakeNetwork.none()));
		assertNull(guards.chooseDirectoryGuard());
		assertTrue(guards.getSampledGuards().isEmpty());
	}

	@Test
	public void sampleAndPrimaryGuards() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		assertNotNull(first);
		assertEquals(20, guards.getSampledGuards().size());
		assertEquals(3, guards.getPrimaryGuards().size());
		for(SampledGuard g: guards.getSampledGuards()) {
			assertTrue(net.relay(routerOf(g)).guard);
		}
		/* NUM_USABLE_PRIMARY_GUARDS = 1: always the same guard. */
		assertSame(routerOf(guards.getPrimaryGuards().get(0)), first);
		for(int i = 0; i < 20; i++) {
			assertSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
		}
		assertEquals(20, net.guardState.size());
	}

	@Test
	public void failedPrimaryIsRetriedAfterTenMinutes() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		guards.guardConnectionFailed(first);
		final Router second = guards.chooseRandomGuard(FakeNetwork.none());
		assertSame(routerOf(guards.getPrimaryGuards().get(1)), second);

		net.time.addAndGet(5 * MINUTE);
		assertSame(second, guards.chooseRandomGuard(FakeNetwork.none()));
		net.time.addAndGet(6 * MINUTE);
		assertSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
	}

	@Test
	public void networkChangeRetriesPrimaryGuards() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		guards.guardConnectionFailed(first);
		assertNotSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
		guards.networkChanged();
		assertSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
	}

	@Test
	public void excludedPrimaryIsSkipped() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		final Set<Router> excluded = new HashSet<Router>(Arrays.asList(first));
		final Router other = guards.chooseRandomGuard(excluded);
		assertNotNull(other);
		assertNotSame(first, other);
		assertSame(routerOf(guards.getPrimaryGuards().get(1)), other);
	}

	@Test
	public void nonPrimaryGuardsWhenPrimariesAreDown() throws InterruptedException {
		final EntryGuards guards = newGuards();
		guards.chooseRandomGuard(FakeNetwork.none());
		for(SampledGuard g: guards.getPrimaryGuards()) {
			guards.guardConnectionFailed(routerOf(g));
		}
		final Router a = guards.chooseRandomGuard(FakeNetwork.none());
		assertNotNull(a);
		assertFalse(guards.getPrimaryGuards().contains(find(guards, a)));
		/* The pending guard is skipped while another is available. */
		final Router b = guards.chooseRandomGuard(FakeNetwork.none());
		assertNotSame(a, b);
		/* Sample order: the first two non-primary guards. */
		assertSame(routerOf(guards.getSampledGuards().get(3)), a);
		assertSame(routerOf(guards.getSampledGuards().get(4)), b);
	}

	@Test
	public void usedGuardIsConfirmedAndBecomesFirstPrimary() throws InterruptedException {
		final EntryGuards guards = newGuards();
		guards.chooseRandomGuard(FakeNetwork.none());
		for(SampledGuard g: guards.getPrimaryGuards()) {
			guards.guardConnectionFailed(routerOf(g));
		}
		final Router other = guards.chooseRandomGuard(FakeNetwork.none());
		guards.guardUsed(other);
		final SampledGuard g = find(guards, other);
		assertTrue(g.isConfirmed());
		assertEquals(0, g.getConfirmedIndex());
		assertTrue(g.getConfirmedOn().getTime() <= net.time.get());
		assertSame(g, guards.getPrimaryGuards().get(0));
		assertEquals(3, guards.getPrimaryGuards().size());
		/* The old primaries were reachable again (network came back): one of them stays a primary. */
		assertSame(other, guards.chooseRandomGuard(FakeNetwork.none()));
	}

	@Test
	public void directoryGuardsComeFromThreePrimaries() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Set<Router> seen = new HashSet<Router>();
		for(int i = 0; i < 200; i++) {
			seen.add(guards.chooseDirectoryGuard());
		}
		final Set<Router> primaries = new HashSet<Router>();
		for(SampledGuard g: guards.getPrimaryGuards()) {
			primaries.add(routerOf(g));
		}
		assertEquals(primaries, seen);
	}

	@Test
	public void directoryGuardDoesNotNeedDescriptor() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		net.relay(first).hasDescriptor = false;
		boolean used = false;
		for(int i = 0; i < 100 && !used; i++) {
			used = guards.chooseDirectoryGuard() == first;
		}
		assertTrue(used);
	}

	/*
	 * guard-spec 4.12: a circuit waits for the descriptor of its primary
	 * guard.  A directory server that withholds it must not move the
	 * client to another guard.
	 */
	@Test
	public void circuitWaitsForDescriptorOfPrimaryGuard() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		net.relay(first).hasDescriptor = false;
		for(int i = 0; i < 10; i++) {
			assertNull(guards.chooseRandomGuard(FakeNetwork.none()));
		}
		for(SampledGuard g: guards.getSampledGuards()) {
			assertFalse(g.isConfirmed());
		}
		net.relay(first).hasDescriptor = true;
		assertSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
	}

	/* A primary guard that is down is not waited for: the next one is used. */
	@Test
	public void downPrimaryWithoutDescriptorIsNotWaitedFor() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		net.relay(first).hasDescriptor = false;
		guards.guardConnectionFailed(first);
		assertSame(routerOf(guards.getPrimaryGuards().get(1)), guards.chooseRandomGuard(FakeNetwork.none()));
	}

	/*
	 * The sample comes from the consensus, not from the relays whose
	 * descriptors happen to have arrived: right after the first start a
	 * directory server could otherwise pick the client's guards by serving
	 * only the descriptors of its own.
	 */
	@Test
	public void sampleDoesNotDependOnDescriptors() throws InterruptedException {
		final Set<Router> served = new HashSet<Router>();
		for(int i = 0; i < net.relays.size(); i++) {
			final boolean has = (i < 3);
			net.relays.get(i).hasDescriptor = has;
			if(has) {
				served.add(net.relays.get(i).router);
			}
		}
		final EntryGuards guards = newGuards();
		guards.chooseDirectoryGuard();
		assertEquals(20, guards.getSampledGuards().size());
		int withoutDescriptor = 0;
		for(SampledGuard g: guards.getSampledGuards()) {
			if(!served.contains(routerOf(g))) {
				withoutDescriptor++;
			}
		}
		assertTrue(withoutDescriptor >= 17);

		/* Circuits wait for the primary guard; they do not fall back on a served relay. */
		final Router primary = routerOf(guards.getPrimaryGuards().get(0));
		if(!served.contains(primary)) {
			assertNull(guards.chooseRandomGuard(FakeNetwork.none()));
		}
		for(FakeNetwork.Relay r: net.relays) {
			r.hasDescriptor = true;
		}
		assertSame(primary, guards.chooseRandomGuard(FakeNetwork.none()));
	}

	@Test
	public void stateSurvivesRestart() throws InterruptedException {
		final EntryGuards guards = newGuards();
		guards.chooseRandomGuard(FakeNetwork.none());
		final Router used = routerOf(guards.getSampledGuards().get(5));
		guards.guardUsed(used);

		final EntryGuards again = newGuards();
		assertSame(used, again.chooseRandomGuard(FakeNetwork.none()));
		assertEquals(20, again.getSampledGuards().size());
		for(int i = 0; i < 20; i++) {
			assertEquals(guards.getSampledGuards().get(i).getIdentity(), again.getSampledGuards().get(i).getIdentity());
		}
		final Map<String, String> saved = net.guardState.get(5);
		assertEquals("default", saved.get("in"));
		assertEquals(used.getIdentityHash().toString().toUpperCase(), saved.get("rsa_id").toUpperCase());
		assertEquals("0", saved.get("confirmed_idx"));
		assertNotNull(saved.get("confirmed_on"));
	}

	@Test
	public void unknownFieldsAreKept() throws InterruptedException {
		final EntryGuards guards = newGuards();
		guards.chooseRandomGuard(FakeNetwork.none());
		net.guardState.get(0).put("pb_circ_attempts", "7.000000");
		final EntryGuards again = newGuards();
		again.chooseRandomGuard(FakeNetwork.none());
		again.guardUsed(routerOf(again.getSampledGuards().get(0)));
		assertEquals("7.000000", net.guardState.get(0).get("pb_circ_attempts"));
	}

	@Test
	public void unlistedGuardIsRemovedAfterTwentyDays() throws InterruptedException {
		final EntryGuards guards = newGuards();
		final Router first = guards.chooseRandomGuard(FakeNetwork.none());
		final HexDigest id = first.getIdentityHash();
		net.relay(first).guard = false;
		assertNotSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
		assertNotNull(find(guards, first));

		net.relay(first).running = true;
		net.time.addAndGet(19 * DAY);
		guards.chooseRandomGuard(FakeNetwork.none());
		/* unlisted_since is randomized into the past by up to 4 days. */
		net.time.addAndGet(5 * DAY + MINUTE);
		guards.chooseRandomGuard(FakeNetwork.none());
		for(SampledGuard g: guards.getSampledGuards()) {
			assertFalse(g.getIdentity().equals(id));
		}
		assertTrue(guards.getSampledGuards().size() >= 20);
	}

	@Test
	public void entryNodesRestrictGuards() throws InterruptedException {
		config.setEntryNodes(Arrays.asList(net.relays.get(7).identity.toString()));
		final EntryGuards guards = newGuards();
		for(int i = 0; i < 10; i++) {
			assertSame(net.relays.get(7).router, guards.chooseRandomGuard(FakeNetwork.none()));
		}
	}

	@Test
	public void excludeNodesAreNeverGuards() throws InterruptedException {
		final EntryGuards probe = newGuards();
		final Router first = probe.chooseRandomGuard(FakeNetwork.none());
		config.setExcludeNodes(Arrays.asList(first.getIdentityHash().toString()));
		final EntryGuards guards = newGuards();
		for(int i = 0; i < 10; i++) {
			assertNotSame(first, guards.chooseRandomGuard(FakeNetwork.none()));
		}
	}

	@Test
	public void retrySchedules() {
		assertEquals(10 * MINUTE, EntryGuards.primaryRetryInterval(0));
		assertEquals(90 * MINUTE, EntryGuards.primaryRetryInterval(6 * 60 * MINUTE));
		assertEquals(4 * 60 * MINUTE, EntryGuards.primaryRetryInterval(5 * DAY));
		assertEquals(9 * 60 * MINUTE, EntryGuards.primaryRetryInterval(8 * DAY));
		assertEquals(60 * MINUTE, EntryGuards.retryInterval(0));
		assertEquals(36 * 60 * MINUTE, EntryGuards.retryInterval(8 * DAY));
	}

	private static SampledGuard find(EntryGuards guards, Router r) {
		for(SampledGuard g: guards.getSampledGuards()) {
			if(g.getIdentity().equals(r.getIdentityHash())) {
				return g;
			}
		}
		return null;
	}
}
