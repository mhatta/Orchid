package com.subgraph.orchid.circuits.path;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * Directory requests must go to directory caches (relays with the V2Dir
 * flag), not to the directory authorities.  Relays publish a DirPort of 0
 * since Tor 0.4.6, so a choice based on the DirPort only finds the
 * authorities.
 */
public class CircuitNodeChooserDirectoryTest {

	private static Router router(String name, boolean authority, boolean v2dir, int dirPort) {
		final Router r = createNiceMock(Router.class);
		expect(r.getNickname()).andStubReturn(name);
		expect(r.isRunning()).andStubReturn(true);
		expect(r.isValid()).andStubReturn(true);
		expect(r.isDirectoryAuthority()).andStubReturn(authority);
		expect(r.isDirectoryCache()).andStubReturn(v2dir);
		expect(r.getDirectoryPort()).andStubReturn(dirPort);
		expect(r.hasBandwidth()).andStubReturn(true);
		expect(r.getEstimatedBandwidth()).andStubReturn(1000);
		replay(r);
		return r;
	}

	private static CircuitNodeChooser chooser(List<Router> routers, Router bootstrap) {
		final Directory directory = createNiceMock(Directory.class);
		expect(directory.getAllRouters()).andStubReturn(routers);
		expect(directory.getRandomBootstrapDirectory()).andStubReturn(bootstrap);
		replay(directory);
		return new CircuitNodeChooser(new TorConfigImpl(), directory);
	}

	@Test
	public void testChoosesCachesNotAuthorities() {
		final Router moria1 = router("moria1", true, true, 9231);
		final Router tor26 = router("tor26", true, true, 80);
		final Router noDir = router("NoV2Dir", false, false, 0);
		final List<Router> caches = Arrays.asList(
				router("cache1", false, true, 0),
				router("cache2", false, true, 0),
				router("cache3", false, true, 0));
		final List<Router> all = new ArrayList<Router>(caches);
		all.add(moria1);
		all.add(tor26);
		all.add(noDir);

		final CircuitNodeChooser chooser = chooser(all, null);
		final Set<Router> seen = new HashSet<Router>();
		for(int i = 0; i < 300; i++) {
			final Router r = chooser.chooseDirectory();
			assertTrue("chose "+ r.getNickname(), caches.contains(r));
			seen.add(r);
		}
		assertTrue("load is not spread over the caches", seen.size() == caches.size());
	}

	@Test
	public void testUsesBootstrapDirectoryWithoutConsensus() {
		final Router fallback = router("fallback", false, true, 0);
		final CircuitNodeChooser chooser = chooser(Collections.<Router>emptyList(), fallback);
		assertSame(fallback, chooser.chooseDirectory());
	}

	@Test
	public void testUsesBootstrapDirectoryWhenOnlyAuthoritiesAreKnown() {
		final Router fallback = router("fallback", false, true, 0);
		final List<Router> onlyAuthorities = Arrays.asList(router("moria1", true, true, 9231));
		final CircuitNodeChooser chooser = chooser(onlyAuthorities, fallback);
		final Router r = chooser.chooseDirectory();
		assertSame(fallback, r);
		assertFalse(r.isDirectoryAuthority());
	}
}
