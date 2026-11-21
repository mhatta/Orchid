package com.subgraph.orchid.circuits;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.DormantListener;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.logging.Logger;

/**
 * Whether Orchid is dormant (Tor's dormant mode, Tor 0.4.0 and later): after
 * {@link TorConfig#getDormantClientTimeout()} without client activity it
 * stops doing anything on its own, so that the device can rest, and the
 * next client request wakes it up.
 *
 * <p>This class only keeps the state and decides when it changes.  What
 * dormancy means is done by the {@link Hooks}: the circuit manager stops
 * and restarts its circuit building, the directory downloader and the
 * padding of the connections.
 */
final class DormantController {
	private static final Logger logger = Logger.getInstance(DormantController.class);

	/** What happens when Orchid becomes dormant or wakes up. */
	interface Hooks {
		void enterDormant();
		void leaveDormant();
	}

	/** Milliseconds from a clock that does not jump with the wall clock. */
	interface Clock {
		long millis();
	}

	final static Clock MONOTONIC = new Clock() {
		public long millis() {
			return TimeUnit.NANOSECONDS.toMillis(System.nanoTime());
		}
	};

	private final TorConfig config;
	private final Hooks hooks;
	private final Clock clock;
	private final List<DormantListener> listeners = new CopyOnWriteArrayList<DormantListener>();

	/*
	 * Changes of state, and the hooks that carry them out, happen one at a
	 * time and in order, so that a wake-up cannot overtake the dormancy it
	 * ends.  The hooks only schedule or cancel work; they do not wait for
	 * the network.
	 */
	private final Object lock = new Object();
	private volatile boolean dormant;
	private volatile long lastActivity;

	DormantController(TorConfig config, Hooks hooks) {
		this(config, hooks, MONOTONIC);
	}

	/* For tests: a clock to set. */
	DormantController(TorConfig config, Hooks hooks, Clock clock) {
		this.config = config;
		this.hooks = hooks;
		this.clock = clock;
		this.lastActivity = clock.millis();
	}

	/* Starting counts as activity: the timeout runs from start(), not from the constructor. */
	void noteStartup() {
		lastActivity = clock.millis();
	}

	boolean isDormant() {
		return dormant;
	}

	/**
	 * An application asked for a stream: Tor's "client activity".  Wakes
	 * Orchid up if it is dormant, before the request waits for a circuit.
	 */
	void noteClientActivity() {
		/*
		 * Under the lock, so that it cannot fall between checkIdle()'s
		 * decision and the dormancy: either checkIdle() sees this activity
		 * and stays awake, or this sees the dormancy and wakes up.
		 * Otherwise the request would wait for a circuit that the stopped
		 * circuit creation task never builds.
		 */
		synchronized(lock) {
			lastActivity = clock.millis();
		}
		if(dormant) {
			setDormant(false, "a new stream request", false);
		}
	}

	/**
	 * Called about once a second while Orchid is awake: become dormant if
	 * there has been no client activity for too long.
	 *
	 * @param hasOpenClientStreams whether streams of applications are open
	 * @return true if Orchid has just become dormant
	 */
	boolean checkIdle(boolean hasOpenClientStreams) {
		if(dormant || !config.getDormantTimeoutEnabled()) {
			return false;
		}
		final long now = clock.millis();
		if(hasOpenClientStreams && config.getDormantTimeoutDisabledByIdleStreams()) {
			// Tor counts an open stream as activity.
			lastActivity = now;
			return false;
		}
		if(now - lastActivity < config.getDormantClientTimeout()) {
			return false;
		}
		return setDormant(true, "no client activity for "+ TimeUnit.MILLISECONDS.toMinutes(now - lastActivity) +" minutes", true);
	}

	/**
	 * Become dormant or wake up on the application's request (Tor's SIGNAL
	 * DORMANT and SIGNAL ACTIVE).  Waking up counts as client activity, so
	 * that Orchid does not fall asleep again at once.
	 *
	 * @return true if the state changed
	 */
	boolean setDormant(boolean value) {
		if(!value) {
			lastActivity = clock.millis();
		}
		return setDormant(value, "the application asked for it", false);
	}

	/*
	 * @param onlyIfIdle become dormant only if there is still no client
	 *        activity for the timeout, checked again under the lock
	 */
	private boolean setDormant(boolean value, String reason, boolean onlyIfIdle) {
		synchronized(lock) {
			if(dormant == value) {
				return false;
			}
			if(onlyIfIdle && clock.millis() - lastActivity < config.getDormantClientTimeout()) {
				return false;
			}
			dormant = value;
			if(value) {
				logger.info("Becoming dormant ("+ reason +"): no circuits are built and no directory information is downloaded until the next request");
				runHook(true);
			} else {
				lastActivity = clock.millis();
				logger.info("Waking up from dormant mode ("+ reason +")");
				runHook(false);
			}
		}
		for(DormantListener l: listeners) {
			try {
				l.dormantStateChanged(value);
			} catch(RuntimeException e) {
				logger.warn("Unexpected exception in a dormant listener: "+ e, e);
			}
		}
		return true;
	}

	private void runHook(boolean enter) {
		try {
			if(enter) {
				hooks.enterDormant();
			} else {
				hooks.leaveDormant();
			}
		} catch(RuntimeException e) {
			logger.warn("Unexpected exception "+ (enter ? "becoming dormant" : "waking up") +": "+ e, e);
		}
	}

	void addListener(DormantListener listener) {
		listeners.add(listener);
	}

	void removeListener(DormantListener listener) {
		listeners.remove(listener);
	}
}
