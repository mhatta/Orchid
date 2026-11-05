package com.subgraph.orchid.circuits;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.data.IPv4Address;

/**
 * Host names from applications and SOCKS clients.  An onion address must
 * never be sent to an exit relay, whatever its case or a trailing dot, and
 * characters that change the BEGIN cell's "host:port" are refused.
 */
public class HostnameTest {
	private static final String ONION = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

	private static void assertRefused(String name) {
		try {
			CircuitManagerImpl.normalizeHostname(name);
			fail("accepted "+ name);
		} catch(OpenFailedException e) {
			// expected
		}
	}

	@Test
	public void testOnionAddressesAreRecognizedInAnyForm() throws Exception {
		assertEquals(ONION, CircuitManagerImpl.normalizeHostname(ONION));
		assertEquals(ONION, CircuitManagerImpl.normalizeHostname(ONION.toUpperCase()));
		assertEquals(ONION, CircuitManagerImpl.normalizeHostname(ONION + "."));
		assertEquals("www."+ ONION, CircuitManagerImpl.normalizeHostname("WWW."+ ONION.toUpperCase() + "."));
	}

	@Test
	public void testOrdinaryNamesKeepTheirCase() throws Exception {
		assertEquals("Example.COM", CircuitManagerImpl.normalizeHostname("Example.COM"));
		assertEquals("example.com", CircuitManagerImpl.normalizeHostname("example.com."));
	}

	@Test
	public void testMalformedNamesAreRefused() {
		assertRefused(null);
		assertRefused("");
		assertRefused(".");
		assertRefused("example.com..");
		assertRefused(".example.com");
		assertRefused("example.com:80");
		assertRefused("exa\u0000mple.com");
		assertRefused("example.com\r\n");
		assertRefused("exa mple.com");
		assertRefused("exämple.com");
		final StringBuilder sb = new StringBuilder();
		while(sb.length() < 256) {
			sb.append("a");
		}
		assertRefused(sb.toString());
	}

	@Test
	public void testInternalAddresses() {
		for(String a: new String[] { "0.0.0.0", "10.1.2.3", "127.0.0.1", "100.64.0.1", "169.254.1.1",
				"172.16.0.1", "172.31.255.255", "192.168.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255" }) {
			assertTrue(a, CircuitManagerImpl.isInternalAddress(IPv4Address.createFromString(a)));
		}
		for(String a: new String[] { "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1",
				"192.0.2.1", "198.51.100.1", "223.255.255.255" }) {
			assertFalse(a, CircuitManagerImpl.isInternalAddress(IPv4Address.createFromString(a)));
		}
	}
}
