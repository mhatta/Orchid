package com.subgraph.orchid.circuits.hs;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.easymock.IAnswer;
import org.junit.Test;

import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.StreamConnectFailedException;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.CircuitManagerImpl;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.directory.downloader.DirectoryDownloaderImpl;

/**
 * How HiddenServiceManager keeps and replaces the rendezvous circuit of a
 * service, and that services do not wait for each other.
 */
public class HiddenServiceCircuitReuseTest {
	/* Two valid v3 addresses: the ed25519 base point and a multiple of it. */
	private static final byte[] BASE_POINT = basePoint();
	private static final String ONION_A = HSV3Address.encode(BASE_POINT) + ".onion";
	private static final String ONION_B = HSV3Address.encode(
			com.subgraph.orchid.crypto.Ed25519.blindPublicKey(BASE_POINT, com.subgraph.orchid.crypto.Ed25519.clampScalar(new byte[32]))) + ".onion";

	private static byte[] basePoint() {
		final byte[] b = new byte[32];
		Arrays.fill(b, (byte) 0x66);
		b[0] = 0x58;
		return b;
	}

	private static HiddenServiceManager manager(Directory directory) {
		final TorConfig config = new TorConfigImpl();
		final ConnectionCache cc = createNiceMock(ConnectionCache.class);
		replay(cc);
		final CircuitManagerImpl cm = new CircuitManagerImpl(config, new DirectoryDownloaderImpl(config, null), directory, cc, null);
		return new HiddenServiceManager(config, directory, cm);
	}

	private static Directory directoryWithoutConsensus() {
		final Directory d = createNiceMock(Directory.class);
		replay(d);
		return d;
	}

	private static HiddenServiceCircuit circuit(boolean connected, boolean markedForClose) {
		final HiddenServiceCircuit c = createNiceMock(HiddenServiceCircuit.class);
		expect(c.isConnected()).andStubReturn(connected);
		expect(c.isMarkedForClose()).andStubReturn(markedForClose);
		replay(c);
		return c;
	}

	@Test
	public void testLiveCircuitIsKept() {
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION_A));
		final HiddenServiceCircuit c = circuit(true, false);
		hs.setCircuit(c);
		assertSame(c, hs.getCircuit());
	}

	@Test
	public void testDestroyedCircuitIsDropped() {
		// A circuit torn down by a DESTROY is not connected, but not marked for close either.
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION_A));
		hs.setCircuit(circuit(false, false));
		assertNull(hs.getCircuit());
	}

	@Test
	public void testCircuitMarkedForCloseIsDropped() {
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION_A));
		hs.setCircuit(circuit(true, true));
		assertNull(hs.getCircuit());
	}

	@Test
	public void testDiscardOnlyForgetsThatCircuit() {
		final HiddenService hs = new HiddenService(new TorConfigImpl(), HSV3Address.parse(ONION_A));
		final HiddenServiceCircuit current = circuit(true, false);
		hs.setCircuit(current);
		hs.discardCircuit(circuit(true, false));
		assertSame(current, hs.getCircuit());
		hs.discardCircuit(current);
		assertNull(hs.getCircuit());
	}

	@Test(timeout = 20000)
	public void testStreamOnCircuitThatDiedIsRetriedOnANewCircuit() throws Exception {
		final HiddenServiceManager m = manager(directoryWithoutConsensus());
		final HiddenService hs = m.getHiddenServiceForOnion(ONION_A);
		final HiddenServiceCircuit dying = createNiceMock(HiddenServiceCircuit.class);
		expect(dying.isMarkedForClose()).andStubReturn(false);
		expect(dying.isConnected()).andReturn(true);      // still alive when picked from the cache
		expect(dying.isConnected()).andStubReturn(false); // gone when the stream fails
		expect(dying.openStream(80, 20000)).andThrow(new StreamConnectFailedException(0));
		dying.markForClose();
		replay(dying);
		hs.setCircuit(dying);
		try {
			m.getStreamTo(ONION_A, 80);
			fail("expected OpenFailedException");
		} catch(OpenFailedException e) {
			// The retry tried to open a new circuit, which needs a consensus.
			assertTrue(e.getMessage(), e.getMessage().contains("consensus"));
		}
		verify(dying);
		assertNull(hs.getCircuit());
	}

	@Test(timeout = 20000)
	public void testStreamRefusedOnLiveCircuitIsNotRetried() throws Exception {
		final HiddenServiceManager m = manager(directoryWithoutConsensus());
		final HiddenService hs = m.getHiddenServiceForOnion(ONION_A);
		// The service refuses the port; the circuit itself is fine.
		final HiddenServiceCircuit live = createNiceMock(HiddenServiceCircuit.class);
		expect(live.isConnected()).andStubReturn(true);
		expect(live.isMarkedForClose()).andStubReturn(false);
		expect(live.openStream(80, 20000)).andThrow(new StreamConnectFailedException(0));
		replay(live);
		hs.setCircuit(live);
		try {
			m.getStreamTo(ONION_A, 80);
			fail("expected OpenFailedException");
		} catch(OpenFailedException e) {
			assertTrue(e.getMessage(), e.getMessage().startsWith("Failed to open stream"));
		}
		assertSame(live, hs.getCircuit());
	}

	@Test(timeout = 20000)
	public void testSlowServiceDoesNotHoldUpOthers() throws Exception {
		// Opening a circuit to A blocks (here: inside the consensus lookup) for 4 seconds.
		final CountDownLatch insideA = new CountDownLatch(1);
		final Directory directory = createNiceMock(Directory.class);
		expect(directory.getCurrentConsensusDocument()).andStubAnswer(new IAnswer<ConsensusDocument>() {
			public ConsensusDocument answer() throws Throwable {
				insideA.countDown();
				Thread.sleep(4000);
				return null;
			}
		});
		replay(directory);
		final HiddenServiceManager m = manager(directory);

		// B already has a circuit.
		final Stream streamToB = createNiceMock(Stream.class);
		replay(streamToB);
		final HiddenServiceCircuit circuitToB = createNiceMock(HiddenServiceCircuit.class);
		expect(circuitToB.isConnected()).andStubReturn(true);
		expect(circuitToB.openStream(443, 20000)).andStubReturn(streamToB);
		replay(circuitToB);
		m.getHiddenServiceForOnion(ONION_B).setCircuit(circuitToB);

		final Thread a = new Thread(new Runnable() {
			public void run() {
				try {
					m.getStreamTo(ONION_A, 80);
				} catch(Exception expected) {
					// no consensus
				}
			}
		});
		a.setDaemon(true);
		a.start();
		assertTrue(insideA.await(5, TimeUnit.SECONDS));

		final long start = System.nanoTime();
		assertSame(streamToB, m.getStreamTo(ONION_B, 443));
		final long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		assertTrue("stream to B waited "+ waited +" ms for A", waited < 1000);
	}

	@Test(timeout = 20000)
	public void testWaitForInternalCircuitIsBounded() throws Exception {
		final TorConfig config = new TorConfigImpl();
		final Directory d = directoryWithoutConsensus();
		final ConnectionCache cc = createNiceMock(ConnectionCache.class);
		replay(cc);
		final CircuitManagerImpl cm = new CircuitManagerImpl(config, new DirectoryDownloaderImpl(config, null), d, cc, null);
		final long start = System.nanoTime();
		try {
			cm.getCleanInternalCircuit(300);
			fail("expected TimeoutException");
		} catch(TimeoutException expected) {
			final long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
			assertTrue("waited "+ waited +" ms", waited >= 250 && waited < 5000);
		}
	}
}
