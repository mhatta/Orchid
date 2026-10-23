package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;

/**
 * Circuit level flow control with authenticated (version 1) SENDMEs,
 * proposal 289.  Relays close circuits on which they receive version 0
 * SENDMEs, so a client that downloads more than about 500 KB over one
 * circuit must send version 1 SENDMEs carrying the right digest.
 */
public class SendmeTest {
	private final static int EXIT = 2;
	private final static int STREAM_ID = 1;

	private static List<RelayCell> circuitSendmes(FakeRelay relay, int hop) {
		final List<RelayCell> result = new ArrayList<RelayCell>();
		synchronized(relay.hops.get(hop).received) {
			for(RelayCell c: relay.hops.get(hop).received) {
				if(c.getRelayCommand() == RelayCell.RELAY_SENDME && c.getStreamId() == 0) {
					result.add(c);
				}
			}
		}
		return result;
	}

	private static void receiveData(FakeRelay relay, int hop, int count) {
		for(int i = 0; i < count; i++) {
			relay.sendBackward(hop, RelayCell.RELAY_DATA, STREAM_ID, new byte[] { (byte) i, 1, 2, 3 });
		}
	}

	private static void sendData(CircuitImpl circuit, int count) {
		final CircuitNode exit = circuit.getFinalCircuitNode();
		for(int i = 0; i < count; i++) {
			final RelayCell cell = circuit.createRelayCell(RelayCell.RELAY_DATA, STREAM_ID, exit);
			cell.putByteArray(new byte[] { (byte) i, 4, 5, 6 });
			circuit.sendRelayCell(cell);
		}
	}

	@Test
	public void testSendmeTagRules() {
		assertTrue(CircuitNodeImpl.isSendmeAcknowledgedCell(901));
		assertTrue(CircuitNodeImpl.isSendmeAcknowledgedCell(1));
		assertFalse(CircuitNodeImpl.isSendmeAcknowledgedCell(1000));
		assertFalse(CircuitNodeImpl.isSendmeAcknowledgedCell(900));
		assertFalse(CircuitNodeImpl.isSendmeAcknowledgedCell(0));
		assertEquals(20, CircuitNodeImpl.sendmeTag(new byte[32]).length);
	}

	@Test(timeout = 20000)
	public void testReceivingSendsAuthenticatedSendmes() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);

		receiveData(relay, EXIT, 99);
		relay.drain();
		assertEquals(0, circuitSendmes(relay, EXIT).size());

		receiveData(relay, EXIT, 151);
		relay.drain();
		assertNull(relay.getFailure());
		final List<RelayCell> sendmes = circuitSendmes(relay, EXIT);
		assertEquals(2, sendmes.size());
		for(int i = 0; i < 2; i++) {
			final RelayCell sendme = sendmes.get(i);
			assertEquals(CircuitNodeImpl.SENDME_VERSION_AUTHENTICATED, sendme.getByte());
			assertEquals(CircuitNodeImpl.SENDME_TAG_LEN, sendme.getShort());
			final byte[] tag = new byte[CircuitNodeImpl.SENDME_TAG_LEN];
			sendme.getByteArray(tag);
			assertArrayEquals("SENDME "+ i, relay.hops.get(EXIT).sentDataTags.get(i), tag);
			assertEquals(0, sendme.cellBytesRemaining());
		}
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testLongDownload() throws InterruptedException {
		// More than the 1000 cell window: works only if the relay accepts our SENDMEs
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		receiveData(relay, EXIT, 2500);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(25, circuitSendmes(relay, EXIT).size());
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testSendmesFromMiddleHopAreSeparate() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		CircuitExtenderTest.buildCircuit(relay);
		receiveData(relay, 1, 100);
		receiveData(relay, EXIT, 100);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(1, circuitSendmes(relay, 1).size());
		assertEquals(1, circuitSendmes(relay, EXIT).size());
	}

	@Test(timeout = 20000)
	public void testSendingBeyondWindowWithAuthenticatedSendmes() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		sendData(circuit, 2500);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(2500, relay.hops.get(EXIT).dataReceived);
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testVersion0SendmeAccepted() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		relay.hops.get(EXIT).answerSendmeVersion = 0;
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		sendData(circuit, 1200);
		relay.drain();
		assertNull(relay.getFailure());
		assertEquals(1200, relay.hops.get(EXIT).dataReceived);
		assertNull(circuit.getDestroyReason());
	}

	@Test(timeout = 20000)
	public void testWrongSendmeTagClosesCircuit() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		relay.hops.get(EXIT).corruptSendmeTag = true;
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		sendData(circuit, 100);
		relay.drain();
		assertNull(relay.getFailure());
		assertNotNull(circuit.getDestroyReason());
		assertTrue(circuit.getDestroyReason(), circuit.getDestroyReason().contains("protocol error"));
		assertTrue(relay.controlCommands.contains(Cell.DESTROY));
	}

	@Test(timeout = 20000)
	public void testUnsolicitedSendmeClosesCircuit() throws InterruptedException {
		final FakeRelay relay = new FakeRelay(3);
		final CircuitImpl circuit = CircuitExtenderTest.buildCircuit(relay);
		relay.sendBackward(EXIT, RelayCell.RELAY_SENDME, 0, FakeRelay.sendmeV1Payload(new byte[20]));
		relay.drain();
		assertNotNull(circuit.getDestroyReason());
	}
}
