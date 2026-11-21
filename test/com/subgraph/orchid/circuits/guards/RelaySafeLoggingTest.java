package com.subgraph.orchid.circuits.guards;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.SafeLogging;

/**
 * With SafeLogging on, log and error messages give no address of a bridge
 * or a relay Orchid connects to, nor the addresses in socket errors.
 */
public class RelaySafeLoggingTest {

	@After
	public void after() {
		SafeLogging.setEnabled(true);
	}

	private static BridgeRouterImpl bridge() {
		return new BridgeRouterImpl(IPv4Address.createFromString("192.0.2.1"), 443);
	}

	@Test
	public void testBridgeAddressIsLeftOutOfLogs() {
		final BridgeRouterImpl b = bridge();
		assertEquals("[Bridge]", b.toString());
		assertEquals("[Bridge]", SafeLogging.relay(b));
		assertEquals("connection to [Bridge]", "connection to "+ b);
		// The user, who entered the bridge line, still sees it.
		assertEquals("[Bridge 192.0.2.1:443]", b.getNickname());
	}

	@Test
	public void testSafeLoggingOffShowsTheBridge() {
		SafeLogging.setEnabled(false);
		final BridgeRouterImpl b = bridge();
		assertEquals("[Bridge 192.0.2.1:443]", b.toString());
		assertEquals("[Bridge 192.0.2.1:443]", SafeLogging.relay(b));
	}

	@Test
	public void testAddressesAreScrubbedFromMessages() {
		assertEquals("java.net.ConnectException : failed to connect to /[scrubbed] (port 9001) from /[scrubbed] (port 41234) after 10000ms",
				SafeLogging.addresses("java.net.ConnectException : failed to connect to /198.51.100.7 (port 9001) from /10.0.2.15 (port 41234) after 10000ms"));
		assertEquals("from /[scrubbed] and [[scrubbed]]:443 and [scrubbed]",
				SafeLogging.addresses("from /2001:db8::1 and [fe80::1%wlan0]:443 and 2001:db8:0:0:0:0:0:1"));
		assertEquals("Connection refused", SafeLogging.addresses("Connection refused"));
		// Times are left alone.  (A four-part version number such as 0.4.9.5
		// looks like an IPv4 address and is scrubbed too: a small loss.)
		assertEquals("valid-until 2026-11-21 10:00:00, link protocol 5",
				SafeLogging.addresses("valid-until 2026-11-21 10:00:00, link protocol 5"));
		assertEquals(null, SafeLogging.addresses(null));
	}

	@Test
	public void testAddressesAreKeptWhenSafeLoggingIsOff() {
		SafeLogging.setEnabled(false);
		final String m = "failed to connect to /198.51.100.7 (port 9001)";
		assertEquals(m, SafeLogging.addresses(m));
		assertFalse(SafeLogging.isEnabled());
		SafeLogging.setEnabled(true);
		assertTrue(SafeLogging.addresses(m).contains(SafeLogging.SCRUBBED));
	}
}
