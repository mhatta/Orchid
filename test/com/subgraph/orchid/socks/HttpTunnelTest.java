package com.subgraph.orchid.socks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
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
import com.subgraph.orchid.Stream;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.encoders.Base64;

/** The HTTP CONNECT port (HTTPTunnelPort): parsing, authentication, isolation, and a tunnel. */
public class HttpTunnelTest {
	private TorConfigImpl config;
	private SocksPortListenerImpl listener;
	private int port;
	/* host:port|key of every stream asked for. */
	private final List<String> requests = Collections.synchronizedList(new ArrayList<String>());
	private volatile boolean openStreams;

	@Before
	public void before() throws IOException {
		config = new TorConfigImpl();
		final CircuitManager circuitManager = (CircuitManager) Proxy.newProxyInstance(
				CircuitManager.class.getClassLoader(), new Class<?>[] { CircuitManager.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
						if(m.getName().equals("openExitStreamTo")) {
							requests.add(args[0] +":"+ args[1] +"|"+ (args.length == 3 ? args[2] : "<none>"));
							if(!openStreams) {
								throw new OpenFailedException("test: no streams");
							}
							return echoStream();
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
	public void after() {
		listener.stop();
	}

	/* A stream that sends back what it is sent. */
	private static Stream echoStream() throws IOException {
		final PipedInputStream in = new PipedInputStream(4096);
		final PipedOutputStream out = new PipedOutputStream(in);
		return (Stream) Proxy.newProxyInstance(Stream.class.getClassLoader(), new Class<?>[] { Stream.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method m, Object[] args) throws Throwable {
						final String n = m.getName();
						if(n.equals("getInputStream")) {
							return in;
						} else if(n.equals("getOutputStream")) {
							return out;
						} else if(n.equals("close")) {
							out.close();
							return null;
						} else if(m.getReturnType() == int.class) {
							return 0;
						}
						return null;
					}
				});
	}

	private static String basic(String user, String pass) throws IOException {
		return "Basic " + new String(Base64.encode((user + ":" + pass).getBytes("UTF-8")), "US-ASCII");
	}

	private static HttpTunnelClientTask.Request parse(String header, String password) throws HttpTunnelClientTask.HttpError {
		return HttpTunnelClientTask.parse(header, password);
	}

	private static int status(String header, String password) {
		try {
			parse(header, password);
			return 200;
		} catch(HttpTunnelClientTask.HttpError e) {
			return e.status;
		}
	}

	@Test
	public void testParseConnect() throws Exception {
		final HttpTunnelClientTask.Request r = parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", null);
		assertEquals("example.com", r.host);
		assertEquals(443, r.port);
		assertNull(r.isolationKey);
	}

	@Test
	public void testRefusedRequests() {
		assertEquals(405, status("GET http://example.com/ HTTP/1.1\r\n\r\n", null));
		assertEquals(400, status("\u0016\u0003\u0001garbage\r\n\r\n", null));
		assertEquals(400, status("CONNECT example.com HTTP/1.1\r\n\r\n", null));
		assertEquals(400, status("CONNECT example.com:0 HTTP/1.1\r\n\r\n", null));
		assertEquals(400, status("CONNECT example.com:70000 HTTP/1.1\r\n\r\n", null));
		assertEquals(400, status("CONNECT [::1]:443 HTTP/1.1\r\n\r\n", null));
		assertEquals(400, status("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n", null));
	}

	/* The same credentials give the same key as on the SOCKS 5 port. */
	@Test
	public void testCredentialsBecomeTheSocksIsolationKey() throws Exception {
		final HttpTunnelClientTask.Request r = parse("CONNECT example.com:443 HTTP/1.1\r\nproxy-authorization: "+ basic("alice", "x:y") +"\r\n\r\n", null);
		assertEquals(SocksRequest.makeIsolationKey("socks5", "alice".getBytes("UTF-8"), "x:y".getBytes("UTF-8")), r.isolationKey);
		final HttpTunnelClientTask.Request other = parse("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+ basic("bob", "x:y") +"\r\n\r\n", null);
		assertTrue(!r.isolationKey.equals(other.isolationKey));
		// Another scheme is ignored when no password is needed.
		assertNull(parse("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\n\r\n", null).isolationKey);
	}

	@Test
	public void testPasswordRequired() throws Exception {
		assertEquals(407, status("CONNECT example.com:443 HTTP/1.1\r\n\r\n", "s3cret"));
		assertEquals(407, status("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+ basic("u", "wrong") +"\r\n\r\n", "s3cret"));
		assertEquals(407, status("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\n\r\n", "s3cret"));
		assertEquals(200, status("CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: "+ basic("u", "s3cret") +"\r\n\r\n", "s3cret"));
	}

	/* The header is read up to the empty line and not further: the rest is the tunnel's. */
	@Test
	public void testHeaderReadStopsAtEmptyLine() throws Exception {
		final InputStream in = new ByteArrayInputStream("CONNECT a:1 HTTP/1.1\r\n\r\nTLS".getBytes("US-ASCII"));
		assertEquals("CONNECT a:1 HTTP/1.1\r\n\r\n", HttpTunnelClientTask.readHeader(in));
		assertEquals('T', in.read());
		final InputStream bare = new ByteArrayInputStream("CONNECT a:1 HTTP/1.0\n\nX".getBytes("US-ASCII"));
		assertEquals("CONNECT a:1 HTTP/1.0\n\n", HttpTunnelClientTask.readHeader(bare));
	}

	@Test
	public void testOverlongHeaderIsRefused() throws Exception {
		final byte[] b = new byte[HttpTunnelClientTask.MAX_HEADER_BYTES + 10];
		java.util.Arrays.fill(b, (byte) 'a');
		try {
			HttpTunnelClientTask.readHeader(new ByteArrayInputStream(b));
			fail();
		} catch(HttpTunnelClientTask.HttpError e) {
			assertEquals(431, e.status);
		}
	}

	private Socket connect() throws IOException {
		final Socket s = new Socket();
		s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 2000);
		s.setSoTimeout(5000);
		return s;
	}

	private static String readLine(InputStream in) throws IOException {
		final ByteArrayOutputStream b = new ByteArrayOutputStream();
		int c;
		while((c = in.read()) != -1 && c != '\n') {
			b.write(c);
		}
		return new String(b.toByteArray(), "US-ASCII").trim();
	}

	@Test(timeout = 20000)
	public void testTunnel() throws Exception {
		openStreams = true;
		listener.addHttpTunnelPort(port);
		final Socket s = connect();
		try {
			final OutputStream out = s.getOutputStream();
			final InputStream in = s.getInputStream();
			out.write(("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+ basic("alice", "pw") +"\r\n\r\n").getBytes("US-ASCII"));
			assertEquals("HTTP/1.0 200 Connection established", readLine(in));
			assertEquals("", readLine(in));
			out.write("hello\n".getBytes("US-ASCII"));
			assertEquals("hello", readLine(in));
		} finally {
			s.close();
		}
		assertEquals("example.com:443|"+ SocksRequest.makeIsolationKey("socks5", "alice".getBytes("UTF-8"), "pw".getBytes("UTF-8")), requests.get(0));
	}

	/* Clients that cannot send credentials (the Wi-Fi proxy setting) get one key per host. */
	@Test(timeout = 20000)
	public void testIsolateDestAddr() throws Exception {
		config.setIsolateDestAddr(true);
		listener.addHttpTunnelPort(port);
		for(String host: new String[] { "a.example.com", "b.example.com" }) {
			final Socket s = connect();
			try {
				s.getOutputStream().write(("CONNECT "+ host +":443 HTTP/1.1\r\n\r\n").getBytes("US-ASCII"));
				readLine(s.getInputStream());
			} finally {
				s.close();
			}
		}
		assertEquals("a.example.com:443|dest=a.example.com", requests.get(0));
		assertEquals("b.example.com:443|dest=b.example.com", requests.get(1));
	}

	@Test(timeout = 20000)
	public void testFailedStreamGetsBadGateway() throws Exception {
		listener.addHttpTunnelPort(port);
		final Socket s = connect();
		try {
			s.getOutputStream().write("CONNECT example.com:443 HTTP/1.1\r\n\r\n".getBytes("US-ASCII"));
			assertEquals("HTTP/1.0 502 Bad Gateway", readLine(s.getInputStream()));
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testPasswordRequiredOnThePort() throws Exception {
		config.setSocksPassword("s3cret");
		listener.addHttpTunnelPort(port);
		final Socket s = connect();
		try {
			s.getOutputStream().write("CONNECT example.com:443 HTTP/1.1\r\n\r\n".getBytes("US-ASCII"));
			final InputStream in = s.getInputStream();
			assertEquals("HTTP/1.0 407 Proxy Authentication Required", readLine(in));
			assertEquals("Proxy-Authenticate: Basic realm=\"proxy\"", readLine(in));
		} finally {
			s.close();
		}
		assertTrue(requests.isEmpty());
	}

	@Test(expected = TorException.class)
	public void testPortCannotBeBoth() {
		listener.addListeningPort(port);
		listener.addHttpTunnelPort(port);
	}
}
