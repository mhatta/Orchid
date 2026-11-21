package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Test;

import com.subgraph.orchid.DormantListener;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigImpl;

public class DormantControllerTest {
	private final static long MINUTE = 60 * 1000;

	private final TorConfig config = new TorConfigImpl();
	private final AtomicLong now = new AtomicLong(5000000);
	private final List<String> hooks = new ArrayList<String>();
	private final List<Boolean> events = new ArrayList<Boolean>();

	private final DormantController.Clock clock = new DormantController.Clock() {
		public long millis() {
			return now.get();
		}
	};

	private DormantController controller() {
		config.setDormantClientTimeout(30 * MINUTE);
		final DormantController c = new DormantController(config, new DormantController.Hooks() {
			public void enterDormant() {
				hooks.add("enter");
			}
			public void leaveDormant() {
				hooks.add("leave");
			}
		}, clock);
		c.addListener(new DormantListener() {
			public void dormantStateChanged(boolean dormant) {
				events.add(dormant);
			}
		});
		return c;
	}

	@Test
	public void testTorDefaults() {
		final TorConfig c = new TorConfigImpl();
		assertEquals(24 * 60 * MINUTE, c.getDormantClientTimeout());
		assertTrue(c.getDormantTimeoutEnabled());
		assertTrue(c.getDormantTimeoutDisabledByIdleStreams());
		assertTrue(c.getConnectionPadding());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTimeoutBelowTenMinutesIsRefused() {
		new TorConfigImpl().setDormantClientTimeout(10 * MINUTE - 1);
	}

	@Test
	public void testTenMinutesIsAccepted() {
		final TorConfig c = new TorConfigImpl();
		c.setDormantClientTimeout(10 * MINUTE);
		assertEquals(10 * MINUTE, c.getDormantClientTimeout());
	}

	@Test
	public void testBecomesDormantAfterTheTimeout() {
		final DormantController c = controller();
		now.addAndGet(30 * MINUTE - 1);
		assertFalse(c.checkIdle(false));
		assertFalse(c.isDormant());
		now.addAndGet(1);
		assertTrue(c.checkIdle(false));
		assertTrue(c.isDormant());
		assertEquals("[enter]", hooks.toString());
		assertEquals("[true]", events.toString());
		// Once only.
		now.addAndGet(MINUTE);
		assertFalse(c.checkIdle(false));
		assertEquals("[enter]", hooks.toString());
	}

	@Test
	public void testClientActivityPostponesAndWakes() {
		final DormantController c = controller();
		now.addAndGet(20 * MINUTE);
		c.noteClientActivity();
		now.addAndGet(20 * MINUTE);
		assertFalse(c.checkIdle(false));
		now.addAndGet(10 * MINUTE);
		assertTrue(c.checkIdle(false));
		c.noteClientActivity();
		assertFalse(c.isDormant());
		assertEquals("[enter, leave]", hooks.toString());
		assertEquals("[true, false]", events.toString());
		// Woken up: a whole timeout before the next dormancy.
		now.addAndGet(29 * MINUTE);
		assertFalse(c.checkIdle(false));
	}

	@Test
	public void testOpenStreamsCountAsActivity() {
		final DormantController c = controller();
		now.addAndGet(60 * MINUTE);
		assertFalse(c.checkIdle(true));
		// The stream has just ended: the timeout runs from now.
		now.addAndGet(29 * MINUTE);
		assertFalse(c.checkIdle(false));
		now.addAndGet(MINUTE);
		assertTrue(c.checkIdle(false));
	}

	@Test
	public void testIdleStreamsDoNotCountWhenTurnedOff() {
		final DormantController c = controller();
		config.setDormantTimeoutDisabledByIdleStreams(false);
		now.addAndGet(30 * MINUTE);
		assertTrue(c.checkIdle(true));
	}

	@Test
	public void testNoTimeoutWhenDisabled() {
		final DormantController c = controller();
		config.setDormantTimeoutEnabled(false);
		now.addAndGet(1000 * MINUTE);
		assertFalse(c.checkIdle(false));
		// The application can still make it dormant.
		assertTrue(c.setDormant(true));
		assertTrue(c.isDormant());
	}

	@Test
	public void testApplicationRequests() {
		final DormantController c = controller();
		assertTrue(c.setDormant(true));
		assertFalse(c.setDormant(true));
		assertTrue(c.setDormant(false));
		assertFalse(c.setDormant(false));
		assertEquals("[enter, leave]", hooks.toString());
		assertEquals("[true, false]", events.toString());
		// Waking up counts as activity.
		now.addAndGet(29 * MINUTE);
		assertFalse(c.checkIdle(false));
	}

	@Test
	public void testStartupResetsTheTimer() {
		final DormantController c = controller();
		now.addAndGet(29 * MINUTE);
		c.noteStartup();
		now.addAndGet(29 * MINUTE);
		assertFalse(c.checkIdle(false));
	}

	@Test
	public void testExceptionsInHooksAndListenersAreContained() {
		config.setDormantClientTimeout(30 * MINUTE);
		final DormantController c = new DormantController(config, new DormantController.Hooks() {
			public void enterDormant() {
				throw new IllegalStateException("test");
			}
			public void leaveDormant() {
				throw new IllegalStateException("test");
			}
		}, clock);
		c.addListener(new DormantListener() {
			public void dormantStateChanged(boolean dormant) {
				throw new IllegalStateException("test");
			}
		});
		final List<Boolean> seen = new ArrayList<Boolean>();
		c.addListener(new DormantListener() {
			public void dormantStateChanged(boolean dormant) {
				seen.add(dormant);
			}
		});
		assertTrue(c.setDormant(true));
		assertTrue(c.isDormant());
		c.noteClientActivity();
		assertFalse(c.isDormant());
		assertEquals("[true, false]", seen.toString());
	}
}
