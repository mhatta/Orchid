package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.circuits.cells.CellImpl;

/**
 * PADDING_NEGOTIATE (tor-spec 7.2), sent to ask a guard to stop padding a
 * connection while Orchid is dormant or padding is turned off.
 */
public class PaddingNegotiateTest {

	@Test
	public void testStopCellFormat() {
		final Cell cell = ConnectionImpl.createPaddingNegotiateCell(ConnectionImpl.PADDING_COMMAND_STOP);
		assertEquals(Cell.PADDING_NEGOTIATE, cell.getCommand());
		assertEquals(12, cell.getCommand());
		final byte[] wire = CellImpl.toWireBytes(cell, Cell.CIRCID_LEN);
		assertEquals(514, wire.length);
		// Circuit id 0, command 12, version 0, STOP, ito_low_ms 0, ito_high_ms 0.
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 12, 0, 1, 0, 0, 0, 0 }, Arrays.copyOf(wire, 11));
	}

	@Test
	public void testStartCellAsksForTheRelaysDefaults() {
		final byte[] wire = CellImpl.toWireBytes(
				ConnectionImpl.createPaddingNegotiateCell(ConnectionImpl.PADDING_COMMAND_START), Cell.CIRCID_LEN);
		assertArrayEquals(new byte[] { 12, 0, 2, 0, 0, 0, 0 }, Arrays.copyOfRange(wire, 4, 11));
	}

	@Test
	public void testOnlyChangesAreSent() {
		// Wanted and not stopped: the relay pads by default, nothing to say.
		assertEquals(0, ConnectionImpl.paddingCommandToSend(true, false, 5));
		assertEquals(ConnectionImpl.PADDING_COMMAND_STOP, ConnectionImpl.paddingCommandToSend(false, false, 5));
		// Already stopped.
		assertEquals(0, ConnectionImpl.paddingCommandToSend(false, true, 5));
		assertEquals(ConnectionImpl.PADDING_COMMAND_START, ConnectionImpl.paddingCommandToSend(true, true, 5));
	}

	@Test
	public void testNotBeforeLinkProtocol5() {
		assertEquals(0, ConnectionImpl.paddingCommandToSend(false, false, 4));
		assertEquals(0, ConnectionImpl.paddingCommandToSend(false, false, 0));
	}
}
