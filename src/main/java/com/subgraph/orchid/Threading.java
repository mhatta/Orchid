package com.subgraph.orchid;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Factories for the locks and thread pools used by Orchid.
 *
 * <p>Locks used to be created by Guava's <code>CycleDetectingLockFactory</code>,
 * which records the order in which locks are taken and throws when two locks
 * are acquired in opposite orders.  That check is a debugging aid and was the
 * only reason Orchid depended on Guava, so locks are now plain
 * {@link ReentrantLock}s.  The name given to {@link #lock(String)} is kept and
 * shown by the lock's <code>toString()</code>.
 */
public class Threading {

	private Threading() {
	}

	/**
	 * Create a new reentrant lock.
	 *
	 * @param name A name for the lock, shown by its <code>toString()</code>.
	 */
	public static ReentrantLock lock(String name) {
		return new NamedReentrantLock(name);
	}

	/**
	 * @deprecated Lock cycle detection has been removed; this method has no effect.
	 */
	@Deprecated
	public static void warnOnLockCycles() {
	}

	/**
	 * @deprecated Lock cycle detection has been removed; this method has no effect.
	 */
	@Deprecated
	public static void throwOnLockCycles() {
	}

	/**
	 * @deprecated Lock cycle detection has been removed; this method has no effect.
	 */
	@Deprecated
	public static void ignoreLockCycles() {
	}

	public static ExecutorService newPool(final String name) {
		return Executors.newCachedThreadPool(daemonThreadFactory(name));
	}

	public static ScheduledExecutorService newSingleThreadScheduledPool(final String name) {
		return Executors.newSingleThreadScheduledExecutor(daemonThreadFactory(name));
	}

	public static ScheduledExecutorService newScheduledPool(final String name) {
		return Executors.newScheduledThreadPool(1, daemonThreadFactory(name));
	}

	/**
	 * Return a thread factory creating daemon threads named
	 * <code>name-0</code>, <code>name-1</code>, ...
	 */
	static ThreadFactory daemonThreadFactory(final String name) {
		final ThreadFactory backingFactory = Executors.defaultThreadFactory();
		final AtomicLong count = new AtomicLong(0);
		return new ThreadFactory() {
			public Thread newThread(Runnable runnable) {
				final Thread thread = backingFactory.newThread(runnable);
				thread.setName(name + "-" + count.getAndIncrement());
				thread.setDaemon(true);
				return thread;
			}
		};
	}

	private static final class NamedReentrantLock extends ReentrantLock {
		private static final long serialVersionUID = 1L;
		private final String name;

		NamedReentrantLock(String name) {
			this.name = name;
		}

		@Override
		public String toString() {
			/* ReentrantLock.toString() is "class@hash" followed by the state, e.g. "[Unlocked]" */
			final String s = super.toString();
			final int idx = s.indexOf('[');
			return (idx < 0) ? name : (name + s.substring(idx));
		}
	}
}
