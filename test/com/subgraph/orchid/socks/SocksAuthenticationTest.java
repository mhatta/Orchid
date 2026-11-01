package com.subgraph.orchid.socks;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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
import java.util.Collections;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.CircuitManager;
import com.subgraph.orchid.OpenFailedException;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * SOCKS 5 username/password authentication (RFC 1929), the SOCKS password
 * option, and the isolation keys the SOCKS port passes on with each
 * stream request (IsolateSOCKSAuth).
 */
public class SocksAuthenticationTest {
	private static final byte[] CONNECT_EXAMPLE_COM_80;
	static {
		final byte[] host = ascii("example.com");
		final ByteArrayOutputStream b = new ByteArrayOutputStream();
		b.write(5); b.write(1); b.write(0); b.write(3);
		b.write(host.length);
		b.write(host, 0, host.length);
		b.write(0); b.write(80);
		CONNECT_EXAMPLE_COM_80 = b.toByteArray();
	}

	private TorConfigImpl config;
	private SocksPortListenerImpl listener;
	private int port;
	/* The isolation key of every stream the SOCKS port asked for ("<none>" for the two-argument call). */
	private final List<String> requestedKeys = Collections.synchronizedList(new ArrayList<String>());

	private static byte[] ascii(String s) {
		try {
			return s.getBytes("US-ASCII");
		} catch(IOException e) {
			throw new AssertionError(e);
		}
	}

	@Before
	public void before() throws IOException {
		config = new TorConfigImpl();
		final CircuitManager circuitManager = (CircuitManager) Proxy.newProxyInstance(
				CircuitManager.class.getClassLoader(), new Class<?>[] { CircuitManager.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
						if(m.getName().equals("openExitStreamTo")) {
							requestedKeys.add(args.length == 3 ? String.valueOf(args[2]) : "<none>");
							throw new OpenFailedException("test: no streams");
						}
						return null;
					}
				});
		listener = new SocksPortListenerImpl(config, circuitManager);
		final ServerSocket s = new ServerSocket(0);
		port = s.getLocalPort();
		s.close();
		listener.addListeningPort(port);
	}

	@After
	public void after() {
		listener.stop();
	}

	private Socket connect() throws IOException {
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

	private static byte[] userPass(String user, String pass) {
		final byte[] u = ascii(user);
		final byte[] p = ascii(pass);
		final byte[] b = new byte[3 + u.length + p.length];
		b[0] = 1;
		b[1] = (byte) u.length;
		System.arraycopy(u, 0, b, 2, u.length);
		b[2 + u.length] = (byte) p.length;
		System.arraycopy(p, 0, b, 3 + u.length, p.length);
		return b;
	}

	/* Authenticate with user/pass, send CONNECT, return the CONNECT reply code. */
	private int connectWithUserPass(String user, String pass) throws IOException {
		final Socket s = connect();
		try {
			final OutputStream out = s.getOutputStream();
			final InputStream in = s.getInputStream();
			out.write(new byte[] { 5, 2, 0, 2 });
			assertArrayEquals("username/password must be chosen when offered", new byte[] { 5, 2 }, read(in, 2));
			out.write(userPass(user, pass));
			final byte[] status = read(in, 2);
			assertEquals(1, status[0]);
			if(status[1] != 0) {
				return -1;
			}
			out.write(CONNECT_EXAMPLE_COM_80);
			return read(in, 2)[1];
		} finally {
			s.close();
		}
	}

	private int connectWithoutAuth() throws IOException {
		final Socket s = connect();
		try {
			final OutputStream out = s.getOutputStream();
			final InputStream in = s.getInputStream();
			out.write(new byte[] { 5, 1, 0 });
			final byte[] method = read(in, 2);
			if((method[1] & 0xFF) == 0xFF) {
				return -1;
			}
			assertEquals(0, method[1]);
			out.write(CONNECT_EXAMPLE_COM_80);
			return read(in, 2)[1];
		} finally {
			s.close();
		}
	}

	private String lastKey() throws InterruptedException {
		for(int i = 0; i < 100 && requestedKeys.isEmpty(); i++) {
			Thread.sleep(20);
		}
		assertFalse("no stream was requested", requestedKeys.isEmpty());
		return requestedKeys.remove(requestedKeys.size() - 1);
	}

	@Test(timeout = 20000)
	public void testNoAuthenticationHasNoIsolationKey() throws Exception {
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, connectWithoutAuth());
		assertEquals("null", lastKey());
	}

	@Test(timeout = 20000)
	public void testCredentialsBecomeTheIsolationKey() throws Exception {
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, connectWithUserPass("alice", "x"));
		final String alice = lastKey();
		assertNotNull(alice);
		assertTrue(alice, alice.startsWith("socks5:"));
		connectWithUserPass("alice", "x");
		assertEquals("same credentials, same key", alice, lastKey());
		connectWithUserPass("bob", "x");
		assertFalse("other user, other key", alice.equals(lastKey()));
		connectWithUserPass("alice", "y");
		assertFalse("other password, other key", alice.equals(lastKey()));
	}

	@Test(timeout = 20000)
	public void testKeysAreUnambiguous() throws Exception {
		connectWithUserPass("a:b", "c");
		final String first = lastKey();
		connectWithUserPass("a", "b:c");
		assertFalse(first.equals(lastKey()));
	}

	@Test(timeout = 20000)
	public void testPasswordRequired() throws Exception {
		config.setSocksPassword("s3cret");
		assertEquals("no authentication must be refused", -1, connectWithoutAuth());
		assertEquals("a wrong password must be refused", -1, connectWithUserPass("alice", "wrong"));
		assertTrue(requestedKeys.isEmpty());
		assertEquals(Socks5Request.SOCKS5_STATUS_CONNECTION_REFUSED, connectWithUserPass("alice", "s3cret"));
		assertTrue(lastKey().startsWith("socks5:"));
	}

	private void socks4Connect(String userId) throws IOException {
		final Socket s = connect();
		try {
			final OutputStream out = s.getOutputStream();
			final ByteArrayOutputStream b = new ByteArrayOutputStream();
			// SOCKS 4a: CONNECT, port 80, address 0.0.0.1, user id, host name
			b.write(new byte[] { 4, 1, 0, 80, 0, 0, 0, 1 });
			b.write(ascii(userId));
			b.write(0);
			b.write(ascii("example.com"));
			b.write(0);
			out.write(b.toByteArray());
			read(s.getInputStream(), 8);
		} catch(IOException e) {
			// the port may close the connection without a reply
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testSocks4UserIdIsolates() throws Exception {
		socks4Connect("");
		assertEquals("null", lastKey());
		socks4Connect("tab1");
		final String tab1 = lastKey();
		assertTrue(tab1, tab1.startsWith("socks4:"));
		socks4Connect("tab2");
		assertFalse(tab1.equals(lastKey()));
	}

	@Test(timeout = 20000)
	public void testSocks4RefusedWhenPasswordRequired() throws Exception {
		config.setSocksPassword("s3cret");
		socks4Connect("tab1");
		Thread.sleep(200);
		assertTrue(requestedKeys.isEmpty());
	}

	@Test
	public void testSocksPasswordIsOffByDefault() {
		assertNull(new TorConfigImpl().getSocksPassword());
	}
}
