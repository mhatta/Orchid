package com.subgraph.orchid.sockets;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;

import org.junit.Test;

/** AndroidSocket reports its connection state without reflection. */
public class AndroidSocketTest {
	/* An OrchidSocketImpl whose connect succeeds or fails without Tor. */
	private static OrchidSocketImpl impl(final boolean succeed) {
		return new OrchidSocketImpl(null) {
			@Override
			protected void connect(SocketAddress address, int timeout) throws IOException {
				if(!succeed) {
					throw new IOException("refused");
				}
			}
			@Override
			protected void close() {
			}
		};
	}

	@Test
	public void testConnectedAfterConnect() throws IOException {
		final AndroidSocket s = new AndroidSocket(impl(true));
		assertFalse(s.isConnected());
		s.connect(InetSocketAddress.createUnresolved("example.onion", 80));
		assertTrue(s.isConnected());
		try {
			s.connect(InetSocketAddress.createUnresolved("example.com", 80));
			fail("expected SocketException");
		} catch(SocketException expected) {
		}
	}

	@Test
	public void testNotConnectedAfterFailure() throws IOException {
		final AndroidSocket s = new AndroidSocket(impl(false));
		try {
			s.connect(InetSocketAddress.createUnresolved("example.com", 80));
			fail("expected IOException");
		} catch(IOException expected) {
		}
		assertFalse(s.isConnected());
	}

	@Test
	public void testNoReflection() {
		// No field of java.net.Socket is touched any more.
		for(java.lang.reflect.Field f: AndroidSocket.class.getDeclaredFields()) {
			assertFalse(f.getName(), java.lang.reflect.Field.class.isAssignableFrom(f.getType()));
		}
	}
}
