package com.subgraph.orchid.circuits;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.Connection;
import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;

/**
 * A circuit that is destroyed while it is being built must fail at once,
 * with the reason, rather than after the 30 second build timeout.
 */
public class CircuitDestroyTest {
	/* far below CircuitIO.CIRCUIT_BUILD_TIMEOUT_MS */
	private static final long PROMPT_MS = 5000;

	private static CircuitImpl buildingCircuit() {
		final TorConfig config = new TorConfigImpl();
		final Directory directory = createNiceMock(Directory.class);
		final ConnectionCache connectionCache = createNiceMock(ConnectionCache.class);
		final Connection connection = createNiceMock(Connection.class);
		replay(directory, connectionCache, connection);
		final CircuitManagerImpl circuitManager = new CircuitManagerImpl(config,
				new DirectoryDownloaderImpl(config, null), directory, connectionCache, null);
		final CircuitImpl circuit = (CircuitImpl) CircuitImpl.createDirectoryCircuit(circuitManager);
		circuit.notifyCircuitBuildStart();
		circuit.bindToConnection(connection);
		return circuit;
	}

	private static void deliverDestroyLater(final CircuitImpl circuit) {
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					Thread.sleep(200);
				} catch (InterruptedException e) {
					return;
				}
				final Cell destroy = CellImpl.createCell(circuit.getCircuitId(), Cell.DESTROY);
				circuit.deliverControlCell(destroy);
			}
		});
		t.setDaemon(true);
		t.start();
	}

	@Test
	public void testDestroyWakesWaitForCreatedFast() {
		final CircuitImpl circuit = buildingCircuit();
		deliverDestroyLater(circuit);
		final long start = System.currentTimeMillis();
		assertNull(circuit.receiveControlCellResponse());
		assertTrue("waited "+ (System.currentTimeMillis() - start) +" ms",
				System.currentTimeMillis() - start < PROMPT_MS);
		assertNotNull(circuit.getDestroyReason());
		assertTrue(circuit.getDestroyReason(), circuit.getDestroyReason().startsWith("destroyed by relay"));
	}

	@Test
	public void testDestroyWakesWaitForRelayReply() {
		final CircuitImpl circuit = buildingCircuit();
		deliverDestroyLater(circuit);
		final long start = System.currentTimeMillis();
		assertNull(circuit.receiveRelayCell());
		assertTrue("waited "+ (System.currentTimeMillis() - start) +" ms",
				System.currentTimeMillis() - start < PROMPT_MS);
		// a second wait on the destroyed circuit returns at once as well
		final long again = System.currentTimeMillis();
		assertNull(circuit.receiveRelayCell());
		assertTrue(System.currentTimeMillis() - again < PROMPT_MS);
	}

	@Test
	public void testCircuitNotDestroyedHasNoReason() {
		assertNull(buildingCircuit().getDestroyReason());
	}
}
