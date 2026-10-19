package com.subgraph.orchid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Test;

public class ThreadingTest {

	private static final Runnable NOOP = new Runnable() {
		public void run() {
		}
	};

	@Test
	public void testThreadsAreNamedDaemons() {
		final ThreadFactory factory = Threading.daemonThreadFactory("pool");
		final Thread t0 = factory.newThread(NOOP);
		final Thread t1 = factory.newThread(NOOP);
		assertEquals("pool-0", t0.getName());
		assertEquals("pool-1", t1.getName());
		assertTrue(t0.isDaemon());
		assertTrue(t1.isDaemon());
	}

	@Test
	public void testLockIsReentrantAndNamed() {
		final ReentrantLock lock = Threading.lock("testLock");
		assertEquals("testLock[Unlocked]", lock.toString());
		lock.lock();
		try {
			lock.lock();
			assertEquals(2, lock.getHoldCount());
			lock.unlock();
			assertTrue(lock.toString().startsWith("testLock[Locked by thread "));
		} finally {
			lock.unlock();
		}
	}
}
