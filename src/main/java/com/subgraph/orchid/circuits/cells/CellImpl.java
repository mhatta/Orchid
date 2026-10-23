package com.subgraph.orchid.circuits.cells;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import com.subgraph.orchid.Cell;

public class CellImpl implements Cell {

	public static CellImpl createCell(int circuitId, int command) {
		return new CellImpl(circuitId, command);
	}

	public static CellImpl createVarCell(int circuitId, int command, int payloadLength) {
		return new CellImpl(circuitId, command, payloadLength);
	}

	/**
	 * Read one cell from <code>input</code>.
	 *
	 * @param input The stream to read from.
	 * @param wireCircIdLen The width of the circuit id field on the wire: 2
	 *        before the link protocol is negotiated and for link protocol 3,
	 *        4 for link protocol 4 and later.
	 */
	public static CellImpl readFromInputStream(InputStream input, int wireCircIdLen) throws IOException {
		final byte[] header = new byte[wireCircIdLen + 1];
		readAll(input, header);
		final ByteBuffer bb = ByteBuffer.wrap(header);
		final int circuitId = (wireCircIdLen == CIRCID_LEN) ? bb.getInt() : (bb.getShort() & 0xFFFF);
		final int command = bb.get() & 0xFF;

		if(isVariableLengthCommand(command)) {
			return readVarCell(circuitId, command, input);
		}

		final CellImpl cell = new CellImpl(circuitId, command);
		readAll(input, cell.getCellBytes(), CELL_HEADER_LEN, CELL_PAYLOAD_LEN);

		return cell;
	}

	/**
	 * VERSIONS and the commands from 128 up are variable length cells.
	 */
	public static boolean isVariableLengthCommand(int command) {
		return command == VERSIONS || command >= 128;
	}

	/**
	 * Return the bytes of <code>cell</code> as they are sent on a connection
	 * whose circuit id field is <code>wireCircIdLen</code> bytes wide.
	 */
	public static byte[] toWireBytes(Cell cell, int wireCircIdLen) {
		final byte[] bytes = cell.getCellBytes();
		if(wireCircIdLen == CIRCID_LEN) {
			return bytes;
		}
		if(wireCircIdLen != WIRE_CIRCID_LEN_V3) {
			throw new IllegalArgumentException("Bad circuit id length: "+ wireCircIdLen);
		}
		if((cell.getCircuitId() & 0xFFFF0000) != 0) {
			throw new IllegalArgumentException("Circuit id "+ Integer.toHexString(cell.getCircuitId()) +" does not fit in 2 bytes");
		}
		final int skip = CIRCID_LEN - WIRE_CIRCID_LEN_V3;
		final byte[] wire = new byte[bytes.length - skip];
		System.arraycopy(bytes, skip, wire, 0, wire.length);
		return wire;
	}

	private static CellImpl readVarCell(int circuitId, int command, InputStream input) throws IOException {
		final byte[] lengthField = new byte[2];
		readAll(input, lengthField);
		final int length = ((lengthField[0] & 0xFF) << 8) | (lengthField[1] & 0xFF);
		CellImpl cell = new CellImpl(circuitId, command, length);
		readAll(input, cell.getCellBytes(), CELL_VAR_HEADER_LEN, length);
		return cell;
	}

	private static void readAll(InputStream input, byte[] buffer) throws IOException {
		readAll(input, buffer, 0, buffer.length);
	}

	private static void readAll(InputStream input, byte[] buffer, int offset, int length) throws IOException {
		int bytesRead = 0;
		while(bytesRead < length) {
			final int n = input.read(buffer, offset + bytesRead, length - bytesRead);
			if(n == -1)
				throw new EOFException();
			bytesRead += n;
		}
	}

	private final int circuitId;
	private final int command;
	protected final ByteBuffer cellBuffer;

	/* Variable length cell constructor (ie: VERSIONS cells only) */
	private CellImpl(int circuitId, int command, int payloadLength) {
		this.circuitId = circuitId;
		this.command = command;
		this.cellBuffer = ByteBuffer.wrap(new byte[CELL_VAR_HEADER_LEN + payloadLength]);
		cellBuffer.putInt(circuitId);
		cellBuffer.put((byte)command);
		cellBuffer.putShort((short) payloadLength);
		cellBuffer.mark();
	}

	/* Fixed length cell constructor */
	protected CellImpl(int circuitId, int command) {
		this.circuitId = circuitId;
		this.command = command;
		this.cellBuffer = ByteBuffer.wrap(new byte[CELL_LEN]);
		cellBuffer.putInt(circuitId);
		cellBuffer.put((byte) command);
		cellBuffer.mark();
	}

	protected CellImpl(byte[] rawCell) {
		this.cellBuffer = ByteBuffer.wrap(rawCell);
		this.circuitId = cellBuffer.getInt();
		this.command = cellBuffer.get() & 0xFF;
		cellBuffer.mark();
	}
	
	public int getCircuitId() {
		return circuitId;
	}

	public int getCommand() {
		return command;
	}

	public void resetToPayload() {
		cellBuffer.reset();
	}

	public int getByte() {
		return cellBuffer.get() & 0xFF;
	}

	public int getByteAt(int index) {
		return cellBuffer.get(index) & 0xFF;
	}

	public int getShort() {
		return cellBuffer.getShort() & 0xFFFF;
	}

	public int getInt() {
		return cellBuffer.getInt();
	}

	public int getShortAt(int index) {
		return cellBuffer.getShort(index) & 0xFFFF;
	}

	public void getByteArray(byte[] buffer) {
		cellBuffer.get(buffer);
	}

	public int cellBytesConsumed() {
		return cellBuffer.position();
	}

	public int cellBytesRemaining() {
		return cellBuffer.remaining();
	}

	public void putByte(int value) {
		cellBuffer.put((byte) value);
	}

	public void putByteAt(int index, int value) {
		cellBuffer.put(index, (byte) value);
	}

	public void putShort(int value) {
		cellBuffer.putShort((short) value);
	}

	public void putShortAt(int index, int value) {
		cellBuffer.putShort(index, (short) value);
	}

	public void putInt(int value) {
		cellBuffer.putInt(value);
	}

	public void putString(String string) {
		final byte[] bytes = new byte[string.length() + 1];
		for(int i = 0; i < string.length(); i++)
			bytes[i] = (byte) string.charAt(i);
		putByteArray(bytes);
	}

	public void putByteArray(byte[] data) {
		cellBuffer.put(data);
	}

	public void putByteArray(byte[] data, int offset, int length) {
		cellBuffer.put(data, offset, length);
	}

	public byte[] getCellBytes() {
		return cellBuffer.array();
	}

	public String toString() {
		return "Cell: circuit_id="+ Integer.toHexString(circuitId) +" command="+ command +" payload_len="+ cellBuffer.position();
	}

	public static String errorToDescription(int errorCode) {
		switch(errorCode) {
		case ERROR_NONE:
			return "No error reason given";
		case ERROR_PROTOCOL:
			return "Tor protocol violation";
		case ERROR_INTERNAL:
			return "Internal error";
		case ERROR_REQUESTED:
			return "Response to a TRUNCATE command sent from client";
		case ERROR_HIBERNATING:
			return "Not currently operating; trying to save bandwidth.";
		case ERROR_RESOURCELIMIT:
			return "Out of memory, sockets, or circuit IDs.";
		case ERROR_CONNECTFAILED:
			return "Unable to reach server.";
		case ERROR_OR_IDENTITY:
			return "Connected to server, but its OR identity was not as expected.";
		case ERROR_OR_CONN_CLOSED:
			return "The OR connection that was carrying this circuit died.";
		case ERROR_FINISHED:
			return "The circuit has expired for being dirty or old.";
		case ERROR_TIMEOUT:
			return "Circuit construction took too long.";
		case ERROR_DESTROYED:
			return "The circuit was destroyed without client TRUNCATE";
		case ERROR_NOSUCHSERVICE:
			return "Request for unknown hidden service";
		default:
			return "Error code "+ errorCode;
		}
	}
}
