package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.circuits.cells.CellImpl;

/**
 * A relay may answer only the requests we sent, and must keep to the flow
 * control windows.  Cells that nobody waits for used to be queued without
 * limit, so a relay on the circuit could fill the heap with them; such
 * cells now close the circuit, as they do in Tor.
 */
public class UnsolicitedCellTest {
	private final static int EXIT = 2;

	private static void assertClosedForProtocolError(FakeRelay relay, CircuitImpl circuit) throws InterruptedException {
		relay.drain();
		assertNotNull("circuit was not closed", circuit.getDestroyReason());
		assertTrue(circuit.getDestroyReason(), circuit.getDestroyReason().contains("protocol error"));
		assertTrue(relay.controlCommands.contains(Cell.DESTROY));
	}

	@Test(timeout = 20000)
	public void testExtended2WithoutExtendClosesCircuit() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(EXIT, RelayCell.RELAY_EXTENDED2, 0, new byte[] { 0, 0 });
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testResolvedIsNeverExpected() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(EXIT, RelayCell.RELAY_RESOLVED, 7, new byte[] { 1, 2, 3 });
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testOnlyOneReplyPerRequest() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		circuit.sendRelayCell(circuit.createRelayCell(RelayCell.RELAY_COMMAND_INTRODUCE1, 0, circuit.getFinalCircuitNode()));
		relay.drain();
		relay.sendBackward(EXIT, RelayCell.RELAY_COMMAND_INTRODUCE_ACK, 0, new byte[] { 0, 0 });
		assertNull(circuit.getDestroyReason());
		relay.sendBackward(EXIT, RelayCell.RELAY_COMMAND_INTRODUCE_ACK, 0, new byte[] { 0, 0 });
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testRendezvousCellsAfterEstablishRendezvous() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		circuit.sendRelayCell(circuit.createRelayCell(RelayCell.RELAY_COMMAND_ESTABLISH_RENDEZVOUS, 0, circuit.getFinalCircuitNode()));
		relay.drain();
		relay.sendBackward(EXIT, RelayCell.RELAY_COMMAND_RENDEZVOUS_ESTABLISHED, 0, new byte[0]);
		relay.sendBackward(EXIT, RelayCell.RELAY_COMMAND_RENDEZVOUS2, 0, new byte[64]);
		assertEquals(RelayCell.RELAY_COMMAND_RENDEZVOUS_ESTABLISHED, circuit.receiveRelayCell().getRelayCommand());
		assertEquals(RelayCell.RELAY_COMMAND_RENDEZVOUS2, circuit.receiveRelayCell().getRelayCommand());
		assertNull(circuit.getDestroyReason());
		relay.sendBackward(EXIT, RelayCell.RELAY_COMMAND_RENDEZVOUS2, 0, new byte[64]);
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testCreatedOnBuiltCircuitClosesCircuit() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(2);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final Cell created = CellImpl.createCell(circuit.getCircuitId(), Cell.CREATED2);
		created.resetToPayload();
		circuit.deliverControlCell(created);
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 60000)
	public void testDataBeyondStreamWindowClosesCircuit() throws IOException, InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		final byte[] data = new byte[100];
		// The application reads nothing, so no stream SENDME is sent.
		for(int i = 0; i < 500; i++) {
			relay.sendBackward(EXIT, RelayCell.RELAY_DATA, stream.getStreamId(), data);
		}
		relay.drain();
		assertNull(circuit.getDestroyReason());
		assertEquals(500 * data.length, stream.getInputStream().available());

		relay.sendBackward(EXIT, RelayCell.RELAY_DATA, stream.getStreamId(), data);
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testStreamSendmeBeyondWindowClosesCircuit() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		// Nothing was sent on the stream, so its package window is full.
		relay.sendBackward(EXIT, RelayCell.RELAY_SENDME, stream.getStreamId(), new byte[0]);
		assertClosedForProtocolError(relay, circuit);
	}
}
