package com.subgraph.orchid.circuits.path;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.data.IPv4Address;

/**
 * Relays that must not share a circuit: the same relay, relays in one /16,
 * relays that list each other in their "family" lines, and, with Happy
 * Families (proposal 321), relays that share a family ID.
 */
public class FamilyTest {

	private static Router router(String name, int address, Set<String> familyMembers, Set<String> familyIds) {
		final Router r = createNiceMock(Router.class);
		expect(r.getNickname()).andStubReturn(name);
		expect(r.getAddress()).andStubReturn(new IPv4Address(address));
		expect(r.getFamilyMembers()).andStubReturn(familyMembers);
		expect(r.getFamilyIds()).andStubReturn(familyIds);
		replay(r);
		return r;
	}

	private static Set<String> set(String... s) {
		return new HashSet<String>(Arrays.asList(s));
	}

	private static CircuitPathChooser chooser(Router... routers) {
		final Directory directory = createNiceMock(Directory.class);
		for(Router r: routers) {
			expect(directory.getRouterByName(r.getNickname())).andStubReturn(r);
		}
		expect(directory.getAllRouters()).andStubReturn(Arrays.asList(routers));
		replay(directory);
		return CircuitPathChooser.create(Tor.createConfig(), directory);
	}

	private static final Set<String> NONE = Collections.emptySet();

	@Test
	public void testSharedFamilyIdRelatesRouters() {
		final Router a = router("a", 0x01020304, NONE, set("ed25519:one", "ed25519:two"));
		final Router b = router("b", 0x05060708, NONE, set("ed25519:two"));
		final Router c = router("c", 0x090A0B0C, NONE, set("ed25519:three"));
		final CircuitPathChooser chooser = chooser(a, b, c);
		assertTrue(chooser.areRelated(a, b));
		assertFalse(chooser.areRelated(a, c));
	}

	@Test
	public void testMutualFamilyLinesRelateRouters() {
		final Router a = router("a", 0x01020304, set("b"), NONE);
		final Router b = router("b", 0x05060708, set("a"), NONE);
		final Router c = router("c", 0x090A0B0C, set("a"), NONE);
		final CircuitPathChooser chooser = chooser(a, b, c);
		assertTrue(chooser.areRelated(a, b));
		// c claims a, but a does not claim c
		assertFalse(chooser.areRelated(a, c));
	}

	@Test
	public void testSameRouterAndSameSlash16() {
		final Router a = router("a", 0x01020304, NONE, NONE);
		final Router b = router("b", 0x0102FFFF, NONE, NONE);
		final Router c = router("c", 0x01030304, NONE, NONE);
		final CircuitPathChooser chooser = chooser(a, b, c);
		assertTrue(chooser.areRelated(a, a));
		assertTrue(chooser.areRelated(a, b));
		assertFalse(chooser.areRelated(a, c));
	}

	@Test
	public void testMissingFamilyInformationIsTolerated() {
		final Router a = router("a", 0x01020304, null, null);
		final Router b = router("b", 0x05060708, null, null);
		assertFalse(chooser(a, b).areRelated(a, b));
	}
}
