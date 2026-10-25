package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.RelayCell;

/**
 * Relay cells must come from the hop they belong to.  Stream cells (DATA,
 * END, CONNECTED, stream SENDME) come from the hop the stream was opened
 * to, and replies such as RESOLVED or EXTENDED2 from the last hop.  The
 * guard and the middle relay can produce cells that are "recognized" at
 * their own layer, so a cell from any other hop is a protocol violation
 * that closes the circuit (compare TROVE-2021-003 in Tor).
 */
public class RelayCellSourceTest {
	private final static int GUARD = 0;
	private final static int MIDDLE = 1;
	private final static int EXIT = 2;
	private final static byte[] DATA = new byte[] { 'a', 'b', 'c' };

	private static void assertClosedForProtocolError(FakeRelay relay, CircuitImpl circuit) throws InterruptedException {
		relay.drain();
		assertNotNull("circuit was not closed", circuit.getDestroyReason());
		assertTrue(circuit.getDestroyReason(), circuit.getDestroyReason().contains("protocol error"));
		assertTrue(relay.controlCommands.contains(Cell.DESTROY));
	}

	@Test(timeout = 20000)
	public void testDataFromExitReachesStream() throws IOException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		relay.sendBackward(EXIT, RelayCell.RELAY_DATA, stream.getStreamId(), DATA);
		assertEquals(DATA.length, stream.getInputStream().available());
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testDataFromMiddleHopIsRejected() throws IOException, InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		relay.sendBackward(MIDDLE, RelayCell.RELAY_DATA, stream.getStreamId(), DATA);
		assertEquals(0, stream.getInputStream().available());
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testDataFromGuardIsRejected() throws IOException, InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		relay.sendBackward(GUARD, RelayCell.RELAY_DATA, stream.getStreamId(), DATA);
		assertEquals(0, stream.getInputStream().available());
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testEndFromMiddleHopIsRejected() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl stream = circuit.createNewStream();
		relay.sendBackward(MIDDLE, RelayCell.RELAY_END, stream.getStreamId(), new byte[] { RelayCell.REASON_DONE });
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testCellForUnknownStreamFromMiddleHopIsRejected() throws InterruptedException {
		// A stream that is no longer tracked (half closed) was opened to the exit as well.
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(MIDDLE, RelayCell.RELAY_END, 99, new byte[] { RelayCell.REASON_DONE });
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testCellForUnknownStreamFromExitIsIgnored() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(EXIT, RelayCell.RELAY_END, 99, new byte[] { RelayCell.REASON_DONE });
		relay.drain();
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testResolvedFromMiddleHopIsRejected() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(MIDDLE, RelayCell.RELAY_RESOLVED, 7, new byte[] { 1, 2, 3 });
		assertNull(circuit.receiveRelayCell());
		assertClosedForProtocolError(relay, circuit);
	}

	@Test(timeout = 20000)
	public void testTruncatedFromMiddleHopIsDelivered() throws InterruptedException {
		// Any hop may report that the circuit was cut beyond it.
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(MIDDLE, RelayCell.RELAY_TRUNCATED, 0, new byte[] { (byte) Cell.ERROR_CONNECTFAILED });
		final RelayCell reply = circuit.receiveRelayCell();
		assertNotNull(reply);
		assertEquals(RelayCell.RELAY_TRUNCATED, reply.getRelayCommand());
		assertNull(circuit.getDestroyReason());
	}
}
