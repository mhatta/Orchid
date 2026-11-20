package com.subgraph.orchid.socks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * Replies to requests the SOCKS port cannot serve (L17).
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
		assertTrue(response, response.contains("SOCKS"));
	}
}
