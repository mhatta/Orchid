package com.subgraph.orchid.circuits;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;

/**
 * Circuit construction against {@link FakeRelay}: CREATE2 and EXTEND2 with
 * the ntor handshake, and CREATE_FAST only for a first hop without a known
 * ntor key.
 */
public class CircuitExtenderTest {

	static CircuitImpl buildingCircuit(FakeRelay relay) {
		final TorConfig config = new TorConfigImpl();
		final Directory directory = createNiceMock(Directory.class);
		final ConnectionCache connectionCache = createNiceMock(ConnectionCache.class);
		replay(directory, connectionCache);
		final CircuitManagerImpl circuitManager = new CircuitManagerImpl(config,
				new DirectoryDownloaderImpl(config, null), directory, connectionCache, null);
		final CircuitImpl circuit = (CircuitImpl) CircuitImpl.createDirectoryCircuit(circuitManager);
		circuit.notifyCircuitBuildStart();
		circuit.bindToConnection(relay);
		return circuit;
	}

	/** Build a circuit through every hop of <code>relay</code>. */
	static CircuitImpl buildCircuit(FakeRelay relay) {
		final CircuitImpl circuit = buildingCircuit(relay);
		final CircuitExtender extender = new CircuitExtender(circuit);
		extender.createFirstHop(relay.router(0));
		for(int i = 1; i < relay.hops.size(); i++) {
			extender.extendTo(relay.router(i));
		}
		circuit.notifyCircuitBuildCompleted();
		return circuit;
	}

	@Test
	public void testCreate2AndExtend2() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = buildCircuit(relay);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(3, circuit.getCircuitLength());
		assertEquals(Arrays.asList(Cell.CREATE2), relay.controlCommands);
		// IPv4 address, RSA identity and Ed25519 identity
		assertEquals(Arrays.asList(0, 2, 3), relay.hops.get(1).extendLinkSpecifierTypes);
		assertEquals(Arrays.asList(0, 2, 3), relay.hops.get(2).extendLinkSpecifierTypes);
		for(int i = 0; i < 3; i++) {
			assertSame(relay.router(i), circuit.getNodeList().get(i).getRouter());
		}
	}

	@Test
	public void testRelayCellsBothWays() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = buildCircuit(relay);
		final CircuitNode exit = circuit.getFinalCircuitNode();

		circuit.sendRelayCell(circuit.createRelayCell(RelayCell.RELAY_DROP, 0, exit));
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(RelayCell.RELAY_DROP, relay.hops.get(2).received.get(0).getRelayCommand());

		relay.sendBackward(2, RelayCell.RELAY_RESOLVED, 7, new byte[] { 1, 2, 3 });
		final RelayCell reply = circuit.receiveRelayCell();
		assertEquals(RelayCell.RELAY_RESOLVED, reply.getRelayCommand());
		assertEquals(7, reply.getStreamId());
		assertSame(exit, reply.getCircuitNode());
	}

	@Test
	public void testCreateFastWhenFirstHopHasNoNtorKey() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(2, 0);
		final CircuitImpl circuit = buildCircuit(relay);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(2, circuit.getCircuitLength());
		assertEquals(Arrays.asList(Cell.CREATE_FAST), relay.controlCommands);
	}

	@Test
	public void testExtendRequiresNtorKey() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(2, 1);
		final CircuitImpl circuit = buildingCircuit(relay);
		final CircuitExtender extender = new CircuitExtender(circuit);
		extender.createFirstHop(relay.router(0));
		try {
			extender.extendTo(relay.router(1));
			fail();
		} catch(TorException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("no ntor onion key"));
		}
		relay.drain();
		assertNull(relay.getFailure());
		assertTrue(relay.hops.get(0).received.isEmpty());
	}
}
