package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.After;
import org.junit.Test;

/**
 * A new identity at most every 10 seconds, as Tor limits NEWNYM; one asked
 * for sooner is delayed, not dropped, and merged with the others asked for
 * while it waits.
 */
public class NewIdentityLimiterTest {
	private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
	private final AtomicInteger applied = new AtomicInteger();
	private final AtomicLong now = new AtomicLong(1000000);

	private final Runnable action = new Runnable() {
		public void run() {
			applied.incrementAndGet();
		}
	};

	private final NewIdentityLimiter.Clock clock = new NewIdentityLimiter.Clock() {
		public long millis() {
			return now.get();
		}
	};

	@After
	public void after() {
		executor.shutdownNow();
	}

	private static void waitFor(AtomicInteger counter, int value) throws InterruptedException {
		final long deadline = System.currentTimeMillis() + 5000;
		while(counter.get() < value && System.currentTimeMillis() < deadline) {
			Thread.sleep(5);
		}
	}

	@Test
	public void testTorInterval() {
		assertEquals(10 * 1000, NewIdentityLimiter.INTERVAL);
	}

	@Test
	public void testFirstRequestIsImmediate() {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		assertEquals(0, limiter.request());
		assertEquals(1, applied.get());
	}

	@Test
	public void testRequestAfterTheIntervalIsImmediate() {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		limiter.request();
		now.addAndGet(10000);
		assertEquals(0, limiter.request());
		assertEquals(2, applied.get());
	}

	@Test(timeout = 20000)
	public void testEarlyRequestIsDelayedNotDropped() throws InterruptedException {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		limiter.request();
		now.addAndGet(9800);
		// 200 ms left of the interval.
		assertEquals(200, limiter.request());
		assertEquals(1, applied.get());
		waitFor(applied, 2);
		assertEquals(2, applied.get());
	}

	@Test(timeout = 20000)
	public void testRequestsWhileWaitingAreMerged() throws InterruptedException {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		limiter.request();
		now.addAndGet(9700);
		assertEquals(300, limiter.request());
		now.addAndGet(100);
		// The same pending new identity, 200 ms away now.
		assertEquals(200, limiter.request());
		assertEquals(200, limiter.request());
		waitFor(applied, 2);
		Thread.sleep(400);
		assertEquals(2, applied.get());
	}

	@Test(timeout = 20000)
	public void testIntervalCountsFromTheDelayedOne() throws InterruptedException {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		limiter.request();
		now.addAndGet(9900);
		limiter.request();
		waitFor(applied, 2);
		// The delayed one took effect at the clock's current time; the next
		// one has to wait a whole interval from then.
		now.addAndGet(5000);
		assertEquals(5000, limiter.request());
		assertEquals(2, applied.get());
	}

	@Test
	public void testDoneNowWhenTheExecutorIsShutDown() {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		limiter.request();
		executor.shutdownNow();
		now.addAndGet(1000);
		assertEquals(0, limiter.request());
		assertEquals(2, applied.get());
	}

	@Test(timeout = 20000)
	public void testExceptionInDelayedActionDoesNotStopTheLimiter() throws InterruptedException {
		final AtomicInteger calls = new AtomicInteger();
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, new Runnable() {
			public void run() {
				if(calls.incrementAndGet() == 2) {
					throw new IllegalStateException("test");
				}
			}
		}, clock, 10000);
		limiter.request();
		now.addAndGet(9950);
		limiter.request();
		waitFor(calls, 2);
		now.addAndGet(10000);
		assertEquals(0, limiter.request());
		assertEquals(3, calls.get());
	}

	@Test(timeout = 20000)
	public void testConcurrentRequestsApplyOnce() throws InterruptedException {
		final NewIdentityLimiter limiter = new NewIdentityLimiter(executor, action, clock, 10000);
		final Thread[] threads = new Thread[8];
		for(int i = 0; i < threads.length; i++) {
			threads[i] = new Thread(new Runnable() {
				public void run() {
					for(int j = 0; j < 100; j++) {
						limiter.request();
					}
				}
			});
			threads[i].start();
		}
		for(Thread t: threads) {
			t.join();
		}
		// The clock did not move: one immediate, one delayed and pending.
		assertEquals(1, applied.get());
		assertTrue(limiter.request() > 0);
		executor.shutdownNow();
		assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
	}
}
