package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Stream ids are 16 bits and wrap around; an id still in use must not be
 * given to a new stream, which would replace the open one in the table.
 */
public class StreamIdTest {

	@Test(timeout = 20000)
	public void testIdInUseIsSkippedAfterWrapping() {
		final FakeRelay relay = new FakeRelay(2);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		final StreamImpl open = circuit.createNewStream();
		// go round the id space until the next id would be the open stream's again
		for(int i = 0; i < 0xFFFF - 1; i++) {
			circuit.getStatus().nextStreamId();
		}
		final StreamImpl next = circuit.createNewStream();
		assertNotEquals(open.getStreamId(), next.getStreamId());
		assertEquals(2, circuit.getActiveStreams().size());
		assertTrue(circuit.getActiveStreams().contains(open));
	}
}
