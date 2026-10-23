package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;

/*
 * Cell framing and link protocol negotiation (tor-spec sections 3 and 4.1).
 */
public class LinkProtocolTest {

	@Test
	public void testChooseHighestCommonVersion() {
		assertEquals(5, ConnectionHandshake.chooseLinkProtocolVersion(Arrays.asList(1, 2, 3, 4, 5)));
		assertEquals(4, ConnectionHandshake.chooseLinkProtocolVersion(Arrays.asList(3, 4)));
		assertEquals(5, ConnectionHandshake.chooseLinkProtocolVersion(Arrays.asList(5, 6)));
	}

	@Test
	public void testNoCommonVersion() {
		assertEquals(0, ConnectionHandshake.chooseLinkProtocolVersion(Arrays.asList(1, 2, 3)));
		assertEquals(0, ConnectionHandshake.chooseLinkProtocolVersion(Arrays.<Integer>asList()));
	}

	@Test
	public void testVersionsCellUsesTwoByteCircuitId() throws IOException {
		final Cell cell = CellImpl.createVarCell(0, Cell.VERSIONS, 4);
		cell.putShort(4);
		cell.putShort(5);
		final byte[] wire = CellImpl.toWireBytes(cell, Cell.WIRE_CIRCID_LEN_V3);
		assertArrayEquals(new byte[] { 0, 0, 7, 0, 4, 0, 4, 0, 5 }, wire);

		final Cell read = CellImpl.readFromInputStream(new ByteArrayInputStream(wire), Cell.WIRE_CIRCID_LEN_V3);
		assertEquals(Cell.VERSIONS, read.getCommand());
		assertEquals(Arrays.asList(4, 5), ConnectionHandshake.readVersions(read));
	}

	@Test
	public void testReadVersionsLeavesReadPosition() throws IOException {
		final byte[] wire = { 0, 0, 7, 0, 6, 0, 3, 0, 4, 0, 5 };
		final Cell read = CellImpl.readFromInputStream(new ByteArrayInputStream(wire), Cell.WIRE_CIRCID_LEN_V3);
		assertEquals(Arrays.asList(3, 4, 5), ConnectionHandshake.readVersions(read));
		assertEquals(3, read.getShort());
	}

	@Test
	public void testFixedCellWithFourByteCircuitId() throws IOException {
		final int circId = 0x80001234;
		final Cell cell = CellImpl.createCell(circId, Cell.CREATE2);
		cell.putShort(2);
		cell.putShort(3);
		cell.putByteArray(new byte[] { 9, 8, 7 });

		final byte[] wire = CellImpl.toWireBytes(cell, Cell.CIRCID_LEN);
		assertEquals(514, wire.length);
		assertArrayEquals(new byte[] { (byte) 0x80, 0, 0x12, 0x34, 10, 0, 2, 0, 3, 9, 8, 7 }, Arrays.copyOf(wire, 12));

		final Cell read = CellImpl.readFromInputStream(new ByteArrayInputStream(wire), Cell.CIRCID_LEN);
		assertEquals(circId, read.getCircuitId());
		assertEquals(Cell.CREATE2, read.getCommand());
		read.resetToPayload();
		assertEquals(2, read.getShort());
		assertEquals(3, read.getShort());
	}

	@Test
	public void testVarCellWithFourByteCircuitId() throws IOException {
		final byte[] wire = { 0, 0, 0, 0, (byte) Cell.CERTS, 0, 2, 0x55, 0x66 };
		final Cell read = CellImpl.readFromInputStream(new ByteArrayInputStream(wire), Cell.CIRCID_LEN);
		assertEquals(Cell.CERTS, read.getCommand());
		assertEquals(0x55, read.getByte());
		assertEquals(0x66, read.getByte());
		assertEquals(0, read.cellBytesRemaining());
	}

	@Test
	public void testFixedCellWithTwoByteCircuitId() throws IOException {
		final Cell cell = CellImpl.createCell(0x1234, Cell.DESTROY);
		cell.putByte(Cell.ERROR_FINISHED);
		final byte[] wire = CellImpl.toWireBytes(cell, Cell.WIRE_CIRCID_LEN_V3);
		assertEquals(512, wire.length);
		final Cell read = CellImpl.readFromInputStream(new ByteArrayInputStream(wire), Cell.WIRE_CIRCID_LEN_V3);
		assertEquals(0x1234, read.getCircuitId());
		assertEquals(Cell.ERROR_FINISHED, read.getByte());
	}

	@Test
	public void testWideCircuitIdDoesNotFitTwoBytes() {
		final Cell cell = CellImpl.createCell(0x80000001, Cell.DESTROY);
		try {
			CellImpl.toWireBytes(cell, Cell.WIRE_CIRCID_LEN_V3);
			fail();
		} catch(IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testRelayHeaderFollowsCellHeader() {
		final RelayCell cell = new RelayCellImpl(null, 0x80000001, 0x0102, RelayCell.RELAY_DATA);
		cell.putByteArray(new byte[] { 1, 2, 3 });
		cell.setLength();
		final byte[] bytes = cell.getCellBytes();
		assertEquals(514, bytes.length);
		assertEquals(Cell.RELAY, bytes[4]);
		// Relay command, 'recognized', stream id, digest, length
		assertArrayEquals(new byte[] { RelayCell.RELAY_DATA, 0, 0, 1, 2, 0, 0, 0, 0, 0, 3, 1, 2, 3 },
				Arrays.copyOfRange(bytes, Cell.CELL_HEADER_LEN, Cell.CELL_HEADER_LEN + 14));
		assertEquals(Cell.CELL_HEADER_LEN + 11, RelayCell.HEADER_SIZE);
	}
}
