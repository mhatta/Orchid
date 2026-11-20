package com.subgraph.orchid.misc;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.subgraph.orchid.TrafficInfo;

public class TrafficCounterTest {

	@Test
	public void testStartsAtZero() {
		final TrafficInfo info = new TrafficCounter().getTrafficInfo();
		assertEquals(0, info.getBytesRead());
		assertEquals(0, info.getBytesWritten());
		assertEquals(0, info.getStreamBytesRead());
		assertEquals(0, info.getStreamBytesWritten());
	}

	@Test
	public void testCountersAreSeparate() {
		final TrafficCounter c = new TrafficCounter();
		c.addBytesRead(514);
		c.addBytesRead(514);
		c.addBytesWritten(7);
		c.addStreamBytesRead(498);
		c.addStreamBytesWritten(3);
		final TrafficInfo info = c.getTrafficInfo();
		assertEquals(1028, info.getBytesRead());
		assertEquals(7, info.getBytesWritten());
		assertEquals(498, info.getStreamBytesRead());
		assertEquals(3, info.getStreamBytesWritten());
	}

	@Test
	public void testNegativeAndZeroAreIgnored() {
		// read() returns -1 at the end of a stream.
		final TrafficCounter c = new TrafficCounter();
		c.addBytesRead(-1);
		c.addBytesWritten(0);
		c.addStreamBytesRead(-5);
		assertEquals(0, c.getTrafficInfo().getBytesRead());
		assertEquals(0, c.getTrafficInfo().getBytesWritten());
		assertEquals(0, c.getTrafficInfo().getStreamBytesRead());
	}

	@Test
	public void testSnapshotDoesNotChange() {
		final TrafficCounter c = new TrafficCounter();
		c.addBytesRead(10);
		final TrafficInfo before = c.getTrafficInfo();
		c.addBytesRead(10);
		assertEquals(10, before.getBytesRead());
		assertEquals(20, c.getTrafficInfo().getBytesRead());
	}

	@Test(timeout = 20000)
	public void testConcurrentAdds() throws InterruptedException {
		final TrafficCounter c = new TrafficCounter();
		final Thread[] threads = new Thread[8];
		for(int i = 0; i < threads.length; i++) {
			threads[i] = new Thread(new Runnable() {
				public void run() {
					for(int j = 0; j < 10000; j++) {
						c.addBytesWritten(514);
					}
				}
			});
			threads[i].start();
		}
		for(Thread t: threads) {
			t.join();
		}
		assertEquals(8L * 10000 * 514, c.getTrafficInfo().getBytesWritten());
	}
}
