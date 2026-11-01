package com.subgraph.orchid.circuits.hs;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;

import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.config.TorConfigImpl;

/** Streams to one onion service with different isolation keys get rendezvous circuits of their own. */
public class HiddenServiceIsolationTest {
	private static final byte[] BASE_POINT = HiddenServiceCircuitReuseTest.BASE_POINT;
	private static final String ONION = HSV3Address.encode(BASE_POINT) + ".onion";

	private static HiddenServiceCircuit liveCircuit() {
		final HiddenServiceCircuit c = createNiceMock(HiddenServiceCircuit.class);
		expect(c.isConnected()).andStubReturn(true);
		expect(c.isMarkedForClose()).andStubReturn(false);
		replay(c);
		return c;
	}

	@Test
	public void testCircuitsAreKeptPerIsolationKey() {
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION));
		final HiddenServiceCircuit shared = liveCircuit();
		final HiddenServiceCircuit alice = liveCircuit();
		hs.setCircuit(shared);
		hs.setCircuit("socks5:61:78", alice);
		assertSame(shared, hs.getCircuit());
		assertSame(shared, hs.getCircuit(null));
		assertSame(alice, hs.getCircuit("socks5:61:78"));
		assertNull("another key must not get alice's circuit", hs.getCircuit("socks5:62:78"));
	}

	@Test
	public void testDiscardRemovesOnlyThatCircuit() {
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION));
		final HiddenServiceCircuit shared = liveCircuit();
		final HiddenServiceCircuit alice = liveCircuit();
		hs.setCircuit(shared);
		hs.setCircuit("socks5:61:78", alice);
		hs.discardCircuit(alice);
		assertNull(hs.getCircuit("socks5:61:78"));
		assertSame(shared, hs.getCircuit());
	}
}
