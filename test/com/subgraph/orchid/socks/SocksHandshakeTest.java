package com.subgraph.orchid.socks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * Limits on SOCKS clients that connect and do not send their request
 * (L15), and the replies to requests the SOCKS port cannot serve (L17).
 */
public class SocksHandshakeTest {
	private TorConfigImpl config;
	private SocksPortListenerImpl listener;
	private int port;
	private final List<Socket> sockets = new ArrayList<Socket>();

	@Before
	public void before() throws IOException {
		config = new TorConfigImpl();
		final CircuitManager circuitManager = (CircuitManager) Proxy.newProxyInstance(
				CircuitManager.class.getClassLoader(), new Class<?>[] { CircuitManager.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
						if(m.getName().equals("openExitStreamTo")) {
							throw new OpenFailedException("test: no streams");
						}
						return null;
					}
				});
		listener = new SocksPortListenerImpl(config, circuitManager);
		final ServerSocket s = new ServerSocket(0);
		port = s.getLocalPort();
		s.close();
	}

	@After
	public void after() throws IOException {
		for(Socket s: sockets) {
			s.close();
		}
		listener.stop();
	}

	private Socket connect() throws IOException {
		final Socket s = new Socket();
		s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2000);
		s.setSoTimeout(5000);
		sockets.add(s);
		return s;
	}

	private static byte[] readToEof(InputStream in) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] buffer = new byte[512];
		int n;
		while((n = in.read(buffer)) != -1) {
			out.write(buffer, 0, n);
		}
		return out.toByteArray();
	}

	private static void assertClosedWithin(Socket s, long millis) throws IOException {
		final long start = System.nanoTime();
		try {
			while(s.getInputStream().read() != -1) {
				// a reply, if any, before the close
			}
		} catch(SocketTimeoutException e) {
			fail("the SOCKS port did not close the connection");
		} catch(IOException e) {
			// a reset is a close too
		}
		final long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		assertTrue("closed after "+ elapsed +" ms", elapsed < millis);
	}

	@Test
	public void testHandshakeTimeoutIsAtMostTenSeconds() {
		config.setSocksTimeout(0);
		assertEquals(SocksPortListenerImpl.HANDSHAKE_TIMEOUT_MS, listener.getHandshakeTimeout());
		config.setSocksTimeout(500);
		assertEquals(500, listener.getHandshakeTimeout());
		config.setSocksTimeout(120 * 1000);
		assertEquals(SocksPortListenerImpl.HANDSHAKE_TIMEOUT_MS, listener.getHandshakeTimeout());
	}

	/* Sending one byte now and then does not keep the connection open: the time is for the whole request. */
	@Test(timeout = 20000)
	public void testTricklingClientIsDisconnected() throws Exception {
		config.setSocksTimeout(1000);
		listener.addListeningPort(port);
		final Socket s = connect();
		final OutputStream out = s.getOutputStream();
		final long start = System.nanoTime();
		try {
			out.write(5);
			out.write(1);
			for(int i = 0; i < 20; i++) {
				Thread.sleep(300);
				out.write(0);   // never a complete request, each byte well within the 1 s read timeout
			}
			fail("the connection was still open after 6 s");
		} catch(IOException expected) {
			final long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
			assertTrue("closed after "+ elapsed +" ms", elapsed < 4000);
		}
	}

	/* Silent clients fill only the handshake slots; the client after them is refused at once. */
	@Test(timeout = 30000)
	public void testSilentClientsAreLimited() throws Exception {
		listener.addListeningPort(port);
		for(int i = 0; i < SocksPortListenerImpl.MAX_HANDSHAKING_CLIENTS; i++) {
			connect();
		}
		// Let the listener accept them all.
		Thread.sleep(500);
		final Socket refused = connect();
		assertClosedWithin(refused, 3000);
	}

	@Test(timeout = 20000)
	public void testIPv6AddressGetsAddressTypeNotSupported() throws IOException {
		listener.addListeningPort(port);
		final Socket s = connect();
		final OutputStream out = s.getOutputStream();
		out.write(new byte[] { 5, 1, 0 });
		final InputStream in = s.getInputStream();
		assertEquals(5, in.read());
		assertEquals(0, in.read());
		final byte[] request = new byte[4 + 16 + 2];
		request[0] = 5; request[1] = 1; request[2] = 0; request[3] = 4;
		request[4 + 15] = 1;    // ::1
		request[21] = 80;
		out.write(request);
		final byte[] reply = readToEof(in);
		assertEquals(22, reply.length);
		assertEquals(5, reply[0]);
		assertEquals(Socks5Request.SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED, reply[1]);
		assertEquals(4, reply[3]);
	}

	@Test(timeout = 20000)
	public void testUnknownAddressTypeGetsAddressTypeNotSupported() throws IOException {
		listener.addListeningPort(port);
		final Socket s = connect();
		final OutputStream out = s.getOutputStream();
		out.write(new byte[] { 5, 1, 0 });
		final InputStream in = s.getInputStream();
		assertEquals(5, in.read());
		assertEquals(0, in.read());
		out.write(new byte[] { 5, 1, 0, 9, 1, 2, 3, 4 });
		final byte[] reply = readToEof(in);
		assertEquals(10, reply.length);
		assertEquals(Socks5Request.SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED, reply[1]);
		assertEquals(1, reply[3]);
	}

	@Test(timeout = 20000)
	public void testHttpConnectGetsAnErrorPage() throws IOException {
		listener.addListeningPort(port);
		final Socket s = connect();
		s.getOutputStream().write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".getBytes("US-ASCII"));
		final String response = new String(readToEof(s.getInputStream()), "US-ASCII");
		assertTrue(response, response.startsWith("HTTP/1.0 501 "));
		// Nothing a probing program could use to tell that Tor (or SOCKS) listens here.
		assertFalse(response, response.contains("Tor"));
		assertFalse(response, response.contains("SOCKS"));
	}
}
