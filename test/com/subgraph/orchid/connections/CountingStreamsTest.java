package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.misc.TrafficCounter;

public class CountingStreamsTest {

	@Test
	public void testInputCountsBytesRead() throws Exception {
		final TrafficCounter counter = new TrafficCounter();
		final InputStream in = new CountingStreams.In(new ByteArrayInputStream(new byte[100]), counter);
		assertEquals(0, in.read());
		assertEquals(10, in.read(new byte[10], 0, 10));
		assertEquals(20, in.skip(20));
		new DataInputStream(in).readFully(new byte[69]);
		assertEquals(100, counter.getTrafficInfo().getBytesRead());
		// The end of the stream counts nothing.
		assertEquals(-1, in.read());
		assertEquals(-1, in.read(new byte[10], 0, 10));
		assertEquals(100, counter.getTrafficInfo().getBytesRead());
		assertFalse(in.markSupported());
	}

	@Test
	public void testOutputCountsBytesWritten() throws Exception {
		final TrafficCounter counter = new TrafficCounter();
		final ByteArrayOutputStream sink = new ByteArrayOutputStream();
		final OutputStream out = new CountingStreams.Out(sink, counter);
		out.write(1);
		out.write(new byte[] { 2, 3, 4, 5 }, 1, 2);
		assertArrayEquals(new byte[] { 1, 3, 4 }, sink.toByteArray());
		assertEquals(3, counter.getTrafficInfo().getBytesWritten());
		assertEquals(0, counter.getTrafficInfo().getBytesRead());
	}

	@Test
	public void testCellsAreCountedWithTheirWireLength() throws Exception {
		// A fixed size cell on link protocol 4 and later: 4 byte circuit id,
		// command, 509 byte payload.
		final TrafficCounter counter = new TrafficCounter();
		final ByteArrayOutputStream sink = new ByteArrayOutputStream();
		final OutputStream out = new CountingStreams.Out(sink, counter);
		final Cell cell = CellImpl.createCell(0x80000001, Cell.RELAY);
		out.write(CellImpl.toWireBytes(cell, Cell.CIRCID_LEN));
		assertEquals(514, counter.getTrafficInfo().getBytesWritten());

		final InputStream in = new CountingStreams.In(new ByteArrayInputStream(sink.toByteArray()), counter);
		final Cell read = CellImpl.readFromInputStream(in, Cell.CIRCID_LEN);
		assertEquals(Cell.RELAY, read.getCommand());
		assertEquals(514, counter.getTrafficInfo().getBytesRead());
	}
}
