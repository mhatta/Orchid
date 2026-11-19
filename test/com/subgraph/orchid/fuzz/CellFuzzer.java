package com.subgraph.orchid.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.circuits.cells.RelayCellImpl;

/**
 * Fuzz target: cells as they arrive on a link (fixed and variable length,
 * 4-byte circuit ids), and the header of the relay cells among them, as a
 * relay could send them.
 */
public class CellFuzzer {
	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final ByteArrayInputStream input = new ByteArrayInputStream(data);
		while(input.available() > 0) {
			final Cell cell;
			try {
				cell = CellImpl.readFromInputStream(input, 4);
			} catch (IOException e) {
				return; // truncated
			}
			if(cell.getCommand() == Cell.RELAY) {
				try {
					final RelayCell relay = RelayCellImpl.createFromCell(null, cell);
					relay.getRelayCommand();
					relay.getStreamId();
				} catch (TorException e) {
					// refused
				}
			}
		}
	}
}
