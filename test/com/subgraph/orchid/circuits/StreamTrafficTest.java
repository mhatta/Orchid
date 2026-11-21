package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TrafficInfo;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;
import com.subgraph.orchid.misc.TrafficCounter;

/**
 * The data of the applications' streams is counted; Orchid's own directory
 * requests, and the stream control cells, are not.
 */
public class StreamTrafficTest {
	private final static int STREAM_ID = 1;

	private static RelayCell received(int relayCommand, int dataLength) {
		final RelayCellImpl cell = new RelayCellImpl(null, 0x80000001, STREAM_ID, relayCommand);
		cell.putByteArray(new byte[dataLength]);
		cell.setLength();
		return RelayCellImpl.createFromCell(null, cell);
	}

	private static StreamImpl stream(TrafficCounter counter) {
		final ExitCircuitImpl circuit = new ExitCircuitImpl(null, (Router) null);
		return new StreamImpl(circuit, null, STREAM_ID, false, counter);
	}

	@Test
	public void testDataIsCounted() {
		final TrafficCounter counter = new TrafficCounter();
		final StreamImpl s = stream(counter);
		assertTrue(s.addInputCell(received(RelayCell.RELAY_CONNECTED, 8)));
		assertTrue(s.addInputCell(received(RelayCell.RELAY_DATA, 498)));
		assertTrue(s.addInputCell(received(RelayCell.RELAY_DATA, 2)));
		s.countStreamBytesWritten(300);
		final TrafficInfo info = counter.getTrafficInfo();
		assertEquals(500, info.getStreamBytesRead());
		assertEquals(300, info.getStreamBytesWritten());
		// Only the circuit manager's connections count cells.
		assertEquals(0, info.getBytesRead());
	}

	@Test
	public void testEndIsNotCounted() {
		final TrafficCounter counter = new TrafficCounter();
		final StreamImpl s = stream(counter);
		assertTrue(s.addInputCell(received(RelayCell.RELAY_END, 1)));
		assertEquals(0, counter.getTrafficInfo().getStreamBytesRead());
	}

	@Test
	public void testDirectoryStreamsAreNotCounted() {
		final TrafficCounter counter = new TrafficCounter();
		final StreamImpl s = stream(counter);
		s.markDirectoryStream();
		assertTrue(s.addInputCell(received(RelayCell.RELAY_DATA, 498)));
		s.countStreamBytesWritten(100);
		assertEquals(0, counter.getTrafficInfo().getStreamBytesRead());
		assertEquals(0, counter.getTrafficInfo().getStreamBytesWritten());
	}

	@Test
	public void testCellsBeyondTheWindowAreNotCounted() {
		final TrafficCounter counter = new TrafficCounter();
		final StreamImpl s = stream(counter);
		for(int i = 0; i < 500; i++) {
			assertTrue(s.addInputCell(received(RelayCell.RELAY_DATA, 1)));
		}
		// The 501st breaks flow control and is refused, as before.
		assertEquals(false, s.addInputCell(received(RelayCell.RELAY_DATA, 1)));
		assertEquals(500, counter.getTrafficInfo().getStreamBytesRead());
	}

	@Test
	public void testEndReasonNames() {
		assertEquals("DONE", StreamImpl.reasonName(RelayCell.REASON_DONE));
		assertEquals("CONNRESET", StreamImpl.reasonName(RelayCell.REASON_CONNRESET));
		assertEquals("unknown reason", StreamImpl.reasonName(200));
	}

	@Test
	public void testEndOfAnOpenStream() {
		final StreamImpl s = stream(new TrafficCounter());
		assertTrue(s.addInputCell(received(RelayCell.RELAY_CONNECTED, 8)));
		final RelayCellImpl end = new RelayCellImpl(null, 0x80000001, STREAM_ID, RelayCell.RELAY_END);
		end.putByte(RelayCell.REASON_CONNRESET);
		end.setLength();
		// Logged; the stream ends as before.
		assertTrue(s.addInputCell(RelayCellImpl.createFromCell(null, end)));
	}

	@Test
	public void testCircuitWithoutManagerHasNoCounter() {
		final ExitCircuitImpl circuit = new ExitCircuitImpl(null, (Router) null);
		assertNull(circuit.getTrafficCounter());
		// A stream created without a counter counts nothing and does not fail.
		final StreamImpl s = new StreamImpl(circuit, null, STREAM_ID, false);
		assertTrue(s.addInputCell(received(RelayCell.RELAY_DATA, 10)));
		s.countStreamBytesWritten(10);
	}
}
