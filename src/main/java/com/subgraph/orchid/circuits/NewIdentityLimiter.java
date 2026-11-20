package com.subgraph.orchid.circuits;

import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.logging.Logger;

/**
 * At most one new identity every {@link #INTERVAL} milliseconds, as Tor
 * limits NEWNYM.  Each new identity retires the circuits in use, and new
 * ones are built for the next streams, so a button pressed again and again
 * (or a program asking on every request) would build circuits without end:
 * a load on the guards, and a pattern of traffic unlike other clients'.
 *
 * <p>A request that comes too early is not dropped but delayed until the
 * interval has passed, as Tor does; requests that come while one is
 * waiting are merged into it.  So every request is honoured, by a new
 * identity at the time of the request or later, never earlier.
 */
final class NewIdentityLimiter {
	private static final Logger logger = Logger.getInstance(NewIdentityLimiter.class);

	/** Tor's MAX_SIGNEWNYM_RATE: 10 seconds. */
	final static long INTERVAL = 10 * 1000;

	/** Milliseconds from a clock that does not jump with the wall clock. */
	interface Clock {
		long millis();
	}

	final static Clock MONOTONIC = new Clock() {
		public long millis() {
			return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
		}
	};

	private final ScheduledExecutorService executor;
	private final Runnable action;
	private final Clock clock;
	private final long interval;

	private final Object lock = new Object();
	private boolean applied;
	private long lastApplied;
	private ScheduledFuture<?> pending;
	private long pendingAt;

	NewIdentityLimiter(ScheduledExecutorService executor, Runnable action) {
		this(executor, action, MONOTONIC, INTERVAL);
	}

	/* For tests: a clock to set, and a shorter interval. */
	NewIdentityLimiter(ScheduledExecutorService executor, Runnable action, Clock clock, long interval) {
		this.executor = executor;
		this.action = action;
		this.clock = clock;
		this.interval = interval;
	}

	/**
	 * Ask for a new identity.
	 *
	 * @return 0 if the new identity took effect now, or the milliseconds
	 *         until the delayed one does.
	 */
	long request() {
		synchronized(lock) {
			final long now = clock.millis();
			if(pending != null) {
				return Math.max(1, pendingAt - now);
			}
			if(applied && now - lastApplied < interval) {
				final long delay = lastApplied + interval - now;
				if(schedule(delay)) {
					pendingAt = now + delay;
					logger.info("New identity requested too soon after the last one: delaying it by "
							+ (TimeUnit.MILLISECONDS.toSeconds(delay + 999)) +" second(s)");
					return delay;
				}
				/* The executor is shut down (the client is stopping): do it now. */
			}
			applied = true;
			lastApplied = now;
		}
		action.run();
		return 0;
	}

	private boolean schedule(long delay) {
		try {
			pending = executor.schedule(new Runnable() {
				public void run() {
					runPending();
				}
			}, delay, TimeUnit.MILLISECONDS);
			return true;
		} catch(RejectedExecutionException e) {
			return false;
		}
	}

	private void runPending() {
		synchronized(lock) {
			pending = null;
			applied = true;
			lastApplied = clock.millis();
		}
		logger.info("Honouring the delayed new identity request");
		try {
			action.run();
		} catch(RuntimeException e) {
			// The executor would swallow it.
			logger.warn("Unexpected exception applying a delayed new identity: "+ e, e);
		}
	}
}
