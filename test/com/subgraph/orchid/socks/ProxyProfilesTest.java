package com.subgraph.orchid.socks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.ProxyStatistics;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.encoders.Base64;

/**
 * Password profiles (TorConfig#setSocksPasswords), the counts of requests
 * that give only an address (ProxyStatistics) with SafeSocks, and server
 * sockets that the caller keeps (addListeningSocket).
 */
public class ProxyProfilesTest {
	private TorConfigImpl config;
	private CircuitManager circuitManager;
	private final List<SocksPortListenerImpl> listeners = new ArrayList<SocksPortListenerImpl>();
	private SocksPortListenerImpl listener;
	private int socksPort;
	private int httpPort;
	/* The isolation key of every stream asked for. */
	private final List<String> keys = Collections.synchronizedList(new ArrayList<String>());

	@Before
	public void before() throws IOException {
		config = new TorConfigImpl();
		circuitManager = (CircuitManager) Proxy.newProxyInstance(
				CircuitManager.class.getClassLoader(), new Class<?>[] { CircuitManager.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
						if(m.getName().equals("openExitStreamTo")) {
							keys.add(String.valueOf(args.length == 3 ? args[2] : null));
							throw new OpenFailedException("test: no streams");
						}
						return null;
					}
				});
		listener = newListener();
		socksPort = freePort();
		httpPort = freePort();
		listener.addListeningPort(socksPort);
		listener.addHttpTunnelPort(httpPort);
	}

	private SocksPortListenerImpl newListener() {
		final SocksPortListenerImpl l = new SocksPortListenerImpl(config, circuitManager);
		listeners.add(l);
		return l;
	}

	private static int freePort() throws IOException {
		final ServerSocket s = new ServerSocket(0);
		final int p = s.getLocalPort();
		s.close();
		return p;
	}

	@After
	public void after() {
		for(SocksPortListenerImpl l: listeners) {
			l.stop();
		}
	}

	private static Socket connect(int port) throws IOException {
		final Socket s = new Socket();
		s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2000);
		s.setSoTimeout(5000);
		return s;
	}

	private static byte[] read(InputStream in, int n) throws IOException {
		final byte[] b = new byte[n];
		int off = 0;
		while(off < n) {
			final int r = in.read(b, off, n - off);
			if(r < 0) {
				throw new IOException("end of stream after "+ off +" bytes");
			}
			off += r;
		}
		return b;
	}

	private static byte[] ascii(String s) {
		try {
			return s.getBytes("US-ASCII");
		} catch(IOException e) {
			throw new AssertionError(e);
		}
	}

	/* SOCKS 5 CONNECT of a host name, port 80. */
	private static byte[] connectName(String host) {
		final byte[] h = ascii(host);
		final ByteArrayOutputStream b = new ByteArrayOutputStream();
		b.write(5); b.write(1); b.write(0); b.write(3);
		b.write(h.length);
		b.write(h, 0, h.length);
		b.write(0); b.write(80);
		return b.toByteArray();
	}

	private static final byte[] CONNECT_IPV4 = { 5, 1, 0, 1, (byte) 192, 0, 2, 1, 0, 80 };
	private static final byte[] CONNECT_IPV6 = { 5, 1, 0, 4, 0x20, 0x01, 0x0d, (byte) 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80 };

	/*
	 * SOCKS 5 with user/pass (or none, when pass is null); returns the
	 * CONNECT reply code, or -1 if authentication was refused.
	 */
	private int socks(int port, String user, String pass, byte[] connect) throws IOException {
		final Socket s = connect(port);
		try {
			final OutputStream out = s.getOutputStream();
			final InputStream in = s.getInputStream();
			if(pass == null) {
				out.write(new byte[] { 5, 1, 0 });
				if((read(in, 2)[1] & 0xFF) == 0xFF) {
					return -1;
				}
			} else {
				out.write(new byte[] { 5, 1, 2 });
				read(in, 2);
				final byte[] u = ascii(user);
				final byte[] p = ascii(pass);
				final ByteArrayOutputStream b = new ByteArrayOutputStream();
				b.write(1); b.write(u.length); b.write(u, 0, u.length); b.write(p.length); b.write(p, 0, p.length);
				out.write(b.toByteArray());
				if(read(in, 2)[1] != 0) {
					return -1;
				}
			}
			out.write(connect);
			return read(in, 2)[1];
		} catch(IOException e) {
			return -2;
		} finally {
			s.close();
		}
	}

	/* An HTTP CONNECT; returns the status code. */
	private int http(String authority, String user, String pass) throws IOException {
		final Socket s = connect(httpPort);
		try {
			final StringBuilder sb = new StringBuilder("CONNECT "+ authority +" HTTP/1.1\r\n");
			if(pass != null) {
				sb.append("Proxy-Authorization: Basic ")
					.append(new String(Base64.encode((user + ":" + pass).getBytes("UTF-8")), "US-ASCII")).append("\r\n");
			}
			sb.append("\r\n");
			s.getOutputStream().write(sb.toString().getBytes("ISO-8859-1"));
			final byte[] line = read(s.getInputStream(), 12);
			return Integer.parseInt(new String(line, "ISO-8859-1").substring(9, 12));
		} finally {
			s.close();
		}
	}

	/* Counts are recorded by the client threads: wait for them. */
	private ProxyStatistics statsAfter(long requests) throws InterruptedException {
		ProxyStatistics st = listener.getStatistics();
		for(int i = 0; i < 100 && st.getTotal().getRequests() < requests; i++) {
			Thread.sleep(20);
			st = listener.getStatistics();
		}
		assertEquals(requests, st.getTotal().getRequests());
		return st;
	}

	private static Map<String, String> profiles(String... namePassword) {
		final Map<String, String> m = new LinkedHashMap<String, String>();
		for(int i = 0; i < namePassword.length; i += 2) {
			m.put(namePassword[i], namePassword[i + 1]);
		}
		return m;
	}

	@Test(timeout = 20000)
	public void testProfilesRequireOneOfTheirPasswords() throws Exception {
		config.setSocksPasswords(profiles("firefox", "pw-firefox", "chat", "pw-chat"));
		assertEquals(-1, socks(socksPort, null, null, connectName("example.com")));
		assertEquals(-1, socks(socksPort, "u", "wrong", connectName("example.com")));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "any", "pw-firefox", connectName("example.com")));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "any", "pw-chat", connectName("example.com")));
		assertEquals(407, http("example.com:443", "u", "wrong"));
		assertEquals(502, http("example.com:443", "u", "pw-chat"));

		final ProxyStatistics st = statsAfter(3);
		assertEquals(1, st.get("firefox").getRequests());
		assertEquals(2, st.get("chat").getRequests());
		assertEquals(0, st.get(ProxyStatistics.NO_PROFILE).getRequests());
		// Each profile has circuits of its own.
		assertEquals(3, keys.size());
		assertFalse(keys.get(0).equals(keys.get(1)));
	}

	@Test(timeout = 20000)
	public void testSinglePasswordStillWorksBesideProfiles() throws Exception {
		config.setSocksPassword("old");
		config.setSocksPasswords(profiles("app", "new"));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "u", "old", connectName("example.com")));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "u", "new", connectName("example.com")));
		final ProxyStatistics st = statsAfter(2);
		assertEquals(1, st.get(ProxyStatistics.NO_PROFILE).getRequests());
		assertEquals(1, st.get("app").getRequests());
	}

	@Test(timeout = 20000)
	public void testSocks4IsRefusedWithProfiles() throws Exception {
		config.setSocksPasswords(profiles("app", "pw"));
		final Socket s = connect(socksPort);
		try {
			s.getOutputStream().write(new byte[] { 4, 1, 0, 80, 0, 0, 0, 1, 0, 'e', 'x', '.', 'c', 'o', 'm', 0 });
			final byte[] reply = read(s.getInputStream(), 8);
			assertFalse("granted", reply[1] == 90);
		} catch(IOException e) {
			// closed without a reply: refused too
		} finally {
			s.close();
		}
		assertTrue(keys.isEmpty());
	}

	@Test(timeout = 20000)
	public void testProfilesCanChangeWhileRunning() throws Exception {
		config.setSocksPasswords(profiles("app", "one"));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "u", "one", connectName("example.com")));
		config.setSocksPasswords(profiles("app", "two"));
		assertEquals(-1, socks(socksPort, "u", "one", connectName("example.com")));
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, "u", "two", connectName("example.com")));
		config.setSocksPasswords(null);
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, null, null, connectName("example.com")));
	}

	@Test
	public void testProfileValidation() {
		final TorConfigImpl c = new TorConfigImpl();
		assertTrue(c.getSocksPasswords().isEmpty());
		for(Map<String, String> bad: new Map[] { profiles("", "pw"), profiles("a", ""), profiles("a", "pw", "b", "pw") }) {
			try {
				c.setSocksPasswords(bad);
				fail("accepted "+ bad.keySet());
			} catch(IllegalArgumentException e) {
				assertFalse("the message must not give the password", e.getMessage().contains("pw"));
			}
		}
		final StringBuilder longPassword = new StringBuilder();
		for(int i = 0; i < 256; i++) {
			longPassword.append('x');
		}
		try {
			c.setSocksPasswords(profiles("a", longPassword.toString()));
			fail("accepted a password SOCKS 5 cannot carry");
		} catch(IllegalArgumentException e) {
			// expected
		}
		final Map<String, String> m = profiles("a", "1");
		c.setSocksPasswords(m);
		m.put("b", "2");
		assertEquals("a copy is kept", 1, c.getSocksPasswords().size());
		try {
			c.getSocksPasswords().put("c", "3");
			fail("modifiable");
		} catch(UnsupportedOperationException e) {
			// expected
		}
	}

	@Test
	public void testProfileFor() {
		config.setSocksPasswords(profiles("a", "1", "b", "2"));
		assertEquals("a", ProxyAuthentication.profileFor(config, ascii("1")));
		assertEquals("b", ProxyAuthentication.profileFor(config, ascii("2")));
		assertNull(ProxyAuthentication.profileFor(config, ascii("3")));
		assertNull(ProxyAuthentication.authenticate(config, null));
		config.setSocksPasswords(null);
		assertEquals(ProxyStatistics.NO_PROFILE, ProxyAuthentication.authenticate(config, null));
		assertEquals(ProxyStatistics.NO_PROFILE, ProxyAuthentication.authenticate(config, ascii("anything")));
	}

	@Test
	public void testAddressLiterals() {
		assertTrue(ProxyAuthentication.isAddressLiteral("192.0.2.1"));
		assertTrue(ProxyAuthentication.isAddressLiteral("192.0.2.1."));
		assertTrue(ProxyAuthentication.isAddressLiteral("2001:db8::1"));
		assertTrue(ProxyAuthentication.isAddressLiteral("[2001:db8::1]"));
		assertFalse(ProxyAuthentication.isAddressLiteral("example.com"));
		assertFalse(ProxyAuthentication.isAddressLiteral("1.example.com"));
		assertFalse(ProxyAuthentication.isAddressLiteral("1.2.3"));
		assertFalse(ProxyAuthentication.isAddressLiteral(null));
	}

	@Test(timeout = 20000)
	public void testAddressOnlyRequestsAreCounted() throws Exception {
		config.setWarnUnsafeSocks(false);
		socks(socksPort, null, null, connectName("example.com"));
		socks(socksPort, null, null, CONNECT_IPV4);
		socks(socksPort, null, null, connectName("192.0.2.7"));
		socks(socksPort, null, null, CONNECT_IPV6);
		http("192.0.2.8:443", null, null);
		http("[2001:db8::1]:443", null, null);
		http("example.com:443", null, null);
		final ProxyStatistics st = statsAfter(7);
		assertEquals(5, st.getTotal().getAddressOnlyRequests());
		assertEquals(0, st.getTotal().getRefusedUnsafeRequests());
		// Served (here: tried) without SafeSocks, but IPv6, which is not supported yet.
		assertEquals(5, keys.size());
	}

	@Test(timeout = 20000)
	public void testSafeSocksRefusesAddresses() throws Exception {
		config.setSafeSocks(true);
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, socks(socksPort, null, null, connectName("example.com")));
		assertEquals(Socks5Request.SOCKS5_STATUS_FAILURE, socks(socksPort, null, null, CONNECT_IPV4));
		assertEquals(Socks5Request.SOCKS5_STATUS_FAILURE, socks(socksPort, null, null, connectName("192.0.2.7")));
		assertEquals(403, http("192.0.2.8:443", null, null));
		assertEquals(502, http("example.com:443", null, null));
		final ProxyStatistics st = statsAfter(5);
		assertEquals(3, st.getTotal().getAddressOnlyRequests());
		assertEquals(3, st.getTotal().getRefusedUnsafeRequests());
		assertEquals("only the host names were tried", 2, keys.size());
	}

	@Test(timeout = 20000)
	public void testSocks4WithAnAddressIsCounted() throws Exception {
		config.setWarnUnsafeSocks(false);
		final Socket s = connect(socksPort);
		try {
			s.getOutputStream().write(new byte[] { 4, 1, 0, 80, (byte) 192, 0, 2, 1, 0 });
			read(s.getInputStream(), 8);
		} finally {
			s.close();
		}
		assertEquals(1, statsAfter(1).getTotal().getAddressOnlyRequests());
	}

	/* A caller's server socket: served, left open by stop(), and taken over by the next listener. */
	@Test(timeout = 20000)
	public void testCallersSocketOutlivesTheListener() throws Exception {
		final ServerSocket kept = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
		try {
			kept.setSoTimeout(1234);
			final SocksPortListenerImpl first = newListener();
			first.addListeningSocket(kept);
			assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED,
					socks(kept.getLocalPort(), null, null, connectName("example.com")));

			first.stop();
			assertFalse("stop() closed the caller's socket", kept.isClosed());
			assertEquals("the timeout is restored", 1234, kept.getSoTimeout());

			// Between the two listeners, a client waits in the backlog.
			final Socket waiting = connect(kept.getLocalPort());
			try {
				waiting.getOutputStream().write(new byte[] { 5, 1, 0 });
				final SocksPortListenerImpl second = newListener();
				second.addListeningSocket(kept);
				assertEquals(0, read(waiting.getInputStream(), 2)[1]);
				waiting.getOutputStream().write(connectName("example.org"));
				assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, read(waiting.getInputStream(), 2)[1]);
				assertEquals(1, second.getStatistics().getTotal().getRequests());
			} finally {
				waiting.close();
			}
		} finally {
			kept.close();
		}
	}

	@Test(timeout = 20000)
	public void testCallersHttpTunnelSocket() throws Exception {
		final ServerSocket kept = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
		try {
			listener.addHttpTunnelSocket(kept);
			final int saved = httpPort;
			httpPort = kept.getLocalPort();
			assertEquals(502, http("example.com:443", null, null));
			httpPort = saved;
		} finally {
			kept.close();
		}
	}

	@Test
	public void testCallersSocketMustBeBoundAndNew() throws Exception {
		final ServerSocket unbound = new ServerSocket();
		try {
			listener.addListeningSocket(unbound);
			fail("accepted an unbound socket");
		} catch(TorException e) {
			// expected
		} finally {
			unbound.close();
		}
		final ServerSocket closed = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
		closed.close();
		try {
			listener.addListeningSocket(closed);
			fail("accepted a closed socket");
		} catch(TorException e) {
			// expected
		}
		final ServerSocket s = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
		try {
			listener.addListeningSocket(s);
			try {
				listener.addHttpTunnelSocket(s);
				fail("accepted the same port twice");
			} catch(TorException e) {
				// expected
			}
		} finally {
			s.close();
		}
	}
}
