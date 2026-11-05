package com.subgraph.orchid.sockets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.Test;

/**
 * The name a socket asks the exit relay for.  HTTP clients that resolve
 * names themselves (OkHttp) can return OrchidSocketFactory#unresolvedAddress()
 * from their DNS hook, so that the host name, not a locally resolved
 * address, reaches the exit relay.
 */
public class UnresolvedAddressTest {

	@Test
	public void testPlaceholderCarriesTheHostName() {
		final InetAddress a = OrchidSocketFactory.unresolvedAddress("check.torproject.org");
		assertEquals("240.0.0.1", a.getHostAddress());
		assertEquals("check.torproject.org", OrchidSocketImpl.addressToName(a));
		assertEquals("check.torproject.org", OrchidSocketImpl.addressToName(new InetSocketAddress(a, 443)));
	}

	@Test
	public void testUnresolvedSocketAddressKeepsItsName() {
		assertEquals("example.com", OrchidSocketImpl.addressToName(InetSocketAddress.createUnresolved("example.com", 80)));
	}

	@Test
	public void testRealAddressIsUsedAsIs() throws Exception {
		assertEquals("192.0.2.1", OrchidSocketImpl.addressToName(InetAddress.getByAddress(new byte[] { (byte) 192, 0, 2, 1 })));
		// A real address that also carries a name is still that address.
		assertEquals("192.0.2.1", OrchidSocketImpl.addressToName(InetAddress.getByAddress("example.com", new byte[] { (byte) 192, 0, 2, 1 })));
	}

	@Test
	public void testPlainZeroAddressIsNotAName() throws Exception {
		assertEquals("0.0.0.0", OrchidSocketImpl.addressToName(InetAddress.getByAddress(new byte[4])));
	}

	/*
	 * A socket that does not come from Orchid's factory must not reach
	 * anything when connected to the placeholder.  0.0.0.0, the placeholder
	 * before 2.5.0, is the local machine on Linux and Android.
	 */
	@Test
	public void testPlaceholderIsNotALocalAddress() {
		final InetAddress a = OrchidSocketFactory.unresolvedAddress("example.com");
		assertFalse(a.isAnyLocalAddress());
		assertFalse(a.isLoopbackAddress());
		assertFalse(a.isSiteLocalAddress());
		assertFalse(a.isLinkLocalAddress());
		assertFalse(a.isMulticastAddress());
	}

	@Test
	public void testOldPlaceholderIsStillAccepted() throws Exception {
		assertEquals("example.com", OrchidSocketImpl.addressToName(InetAddress.getByAddress("example.com", new byte[4])));
	}
}
