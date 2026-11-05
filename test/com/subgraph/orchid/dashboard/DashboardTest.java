package com.subgraph.orchid.dashboard;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** The dashboard has no authentication, so on Android, where any app can reach it, it stays off. */
public class DashboardTest {

	@Test
	public void testDesktopMayListen() {
		assertTrue(Dashboard.mayListen("OpenJDK 64-Bit Server VM", null));
	}

	@Test
	public void testAndroidMayNotListenUnlessAllowed() {
		assertFalse(Dashboard.mayListen("Dalvik", null));
		assertFalse(Dashboard.mayListen("Dalvik", "yes"));
		assertTrue(Dashboard.mayListen("Dalvik", "true"));
	}
}
