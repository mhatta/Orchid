package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.SafeLogging;

/** Stream destinations are left out of log messages unless SafeLogging is off. */
public class SafeLoggingTest {

	@After
	public void after() {
		SafeLogging.setEnabled(true);
	}

	@Test
	public void testExitRequestsAreScrubbedByDefault() {
		assertTrue(new TorConfigImpl().getSafeLogging());
		assertTrue(SafeLogging.isEnabled());
		final Object lock = new Object();
		assertEquals("[scrubbed]:443", new StreamExitRequest(lock, "example.com", 443).toString());
		assertEquals("[scrubbed]:80", new StreamExitRequest(lock, IPv4Address.createFromString("192.0.2.1"), 80).toString());
	}

	@Test
	public void testConfigTurnsScrubbingOff() {
		final TorConfigImpl config = new TorConfigImpl();
		config.setSafeLogging(false);
		assertFalse(SafeLogging.isEnabled());
		final Object lock = new Object();
		assertEquals("example.com:443", new StreamExitRequest(lock, "example.com", 443).toString());
		assertEquals("192.0.2.1:80", new StreamExitRequest(lock, IPv4Address.createFromString("192.0.2.1"), 80).toString());
		config.setSafeLogging(true);
		assertEquals("[scrubbed]:443", new StreamExitRequest(lock, "example.com", 443).toString());
	}
}
