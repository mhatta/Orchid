package com.subgraph.orchid.socks;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigImpl;

public class SocksPortListenerTest {
	private TorConfig config;
	private SocksPortListenerImpl listener;
	private int port;

	@Before
	public void before() throws IOException {
		config = new TorConfigImpl();
		final CircuitManager circuitManager = createNiceMock(CircuitManager.class);
		replay(circuitManager);
		listener = new SocksPortListenerImpl(config, circuitManager);
		port = freePort();
	}

	@After
	public void after() {
		listener.stop();
	}

	private static int freePort() throws IOException {
		final ServerSocket s = new ServerSocket(0);
		try {
			return s.getLocalPort();
		} finally {
			s.close();
		}
	}

	private Socket connectLoopback() throws IOException {
		final Socket s = new Socket();
		s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2000);
		s.setSoTimeout(5000);
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

	private static InetAddress nonLoopbackAddress() throws IOException {
		for(NetworkInterface ni: Collections.list(NetworkInterface.getNetworkInterfaces())) {
			if(!ni.isUp() || ni.isLoopback()) {
				continue;
			}
			for(InetAddress a: Collections.list(ni.getInetAddresses())) {
				if(a instanceof Inet4Address && !a.isLoopbackAddress()) {
					return a;
				}
			}
		}
		return null;
	}

	@Test
	public void testDefaultListenAddressIsLoopback() {
		assertEquals("127.0.0.1", config.getSocksListenAddress());
	}

	@Test
	public void testNotReachableOnOtherInterfaces() throws IOException {
		final InetAddress other = nonLoopbackAddress();
		Assume.assumeTrue("no non-loopback IPv4 address on this machine", other != null);
		listener.addListeningPort(port);
		connectLoopback().close();
		final Socket s = new Socket();
		try {
			s.connect(new InetSocketAddress(other, port), 2000);
			fail("SOCKS port is reachable on "+ other.getHostAddress());
		} catch(IOException expected) {
			// connection refused
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testHttpRequestGetsAnErrorPage() throws IOException {
		listener.addListeningPort(port);
		final Socket s = connectLoopback();
		try {
			final OutputStream out = s.getOutputStream();
			out.write("GET / HTTP/1.0\r\n\r\n".getBytes("US-ASCII"));
			out.flush();
			final String response = new String(readToEof(s.getInputStream()), "US-ASCII");
			assertTrue(response, response.startsWith("HTTP/1.0 501 "));
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testOverlongSocks4StringIsRejected() throws IOException {
		listener.addListeningPort(port);
		final Socket s = connectLoopback();
		try {
			final OutputStream out = s.getOutputStream();
			// SOCKS 4, CONNECT, port 80, 0.0.0.1 (SOCKS 4a), then a user id that never ends
			out.write(new byte[] { 4, 1, 0, 80, 0, 0, 0, 1 });
			final byte[] junk = new byte[SocksRequest.MAX_STRING_LENGTH + 100];
			java.util.Arrays.fill(junk, (byte) 'a');
			out.write(junk);
			out.flush();
			final byte[] response = readToEof(s.getInputStream());
			assertEquals(8, response.length);
			assertEquals(0x5b, response[1] & 0xFF);
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testSilentClientIsDisconnected() throws IOException {
		config.setSocksTimeout(300);
		listener.addListeningPort(port);
		final Socket s = connectLoopback();
		try {
			final long start = System.nanoTime();
			try {
				assertEquals(-1, s.getInputStream().read());
			} catch(SocketTimeoutException e) {
				fail("Orchid did not close a SOCKS connection that sent nothing");
			}
			assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 4000);
		} finally {
			s.close();
		}
	}
}
