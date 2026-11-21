package com.subgraph.orchid.sockets.sslengine;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.After;
import org.junit.Test;

/**
 * The handshake with engines that, like those of Android 8 and earlier,
 * size their buffers from a session the handshake has not negotiated yet,
 * or ask for more room in the middle of the handshake.  The handshake used
 * to stop at a BUFFER_OVERFLOW, reported as "the connection was closed",
 * and to spin on a BUFFER_UNDERFLOW with a full network buffer.
 */
public class OldEngineHandshakeTest {
	private final static String HOST = "test.orchid.invalid";
	private SSLServerSocket server;

	@After
	public void after() throws IOException {
		if(server != null) {
			server.close();
		}
	}

	/* The test keystore of SSLEngineSSLSocketTest, read through reflection to avoid a copy. */
	private static KeyStore keyStore() throws Exception {
		final java.lang.reflect.Method m = SSLEngineSSLSocketTest.class.getDeclaredMethod("keyStore");
		m.setAccessible(true);
		return (KeyStore) m.invoke(null);
	}

	private static SSLContext clientContext() throws Exception {
		final KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
		trust.load(null, null);
		trust.setCertificateEntry("test", keyStore().getCertificate("test"));
		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(trust);
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, tmf.getTrustManagers(), null);
		return context;
	}

	private void startServer() throws Exception {
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore(), "orchid".toCharArray());
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
		server.setEnabledProtocols(new String[] { "TLSv1.2" });
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					final SSLSocket s = (SSLSocket) server.accept();
					s.startHandshake();
					s.getOutputStream().write("ok".getBytes("US-ASCII"));
					s.getOutputStream().flush();
					s.getInputStream().read();
					s.close();
				} catch(IOException e) {
					// test over
				}
			}
		});
		t.setDaemon(true);
		t.start();
	}

	/* A session that reports small buffer sizes until the handshake is done. */
	private static SSLSession smallSession(final SSLSession real, final int size) {
		return (SSLSession) Proxy.newProxyInstance(SSLSession.class.getClassLoader(), new Class<?>[] { SSLSession.class },
				new InvocationHandler() {
					public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
						if(method.getName().equals("getApplicationBufferSize") || method.getName().equals("getPacketBufferSize")) {
							return size;
						}
						try {
							return method.invoke(real, args);
						} catch(InvocationTargetException e) {
							throw e.getCause();
						}
					}
				});
	}

	/* A real client engine, with an old engine's quirks. */
	private static final class QuirkyEngine extends SSLEngine {
		private final SSLEngine e;
		private final int sessionBufferSize;
		private final AtomicInteger overflowsLeft;

		QuirkyEngine(SSLEngine e, int sessionBufferSize, int overflows) {
			super(e.getPeerHost(), e.getPeerPort());
			this.e = e;
			this.sessionBufferSize = sessionBufferSize;
			this.overflowsLeft = new AtomicInteger(overflows);
		}

		public SSLEngineResult wrap(ByteBuffer[] srcs, int off, int len, ByteBuffer dst) throws SSLException {
			return e.wrap(srcs, off, len, dst);
		}

		public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int off, int len) throws SSLException {
			if(e.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP && src.hasRemaining()
					&& overflowsLeft.getAndDecrement() > 0) {
				return new SSLEngineResult(SSLEngineResult.Status.BUFFER_OVERFLOW, SSLEngineResult.HandshakeStatus.NEED_UNWRAP, 0, 0);
			}
			return e.unwrap(src, dsts, off, len);
		}

		public SSLSession getSession() {
			final SSLSession s = e.getSession();
			return (sessionBufferSize > 0) ? smallSession(s, sessionBufferSize) : s;
		}

		public Runnable getDelegatedTask() { return e.getDelegatedTask(); }
		public void closeInbound() throws SSLException { e.closeInbound(); }
		public boolean isInboundDone() { return e.isInboundDone(); }
		public void closeOutbound() { e.closeOutbound(); }
		public boolean isOutboundDone() { return e.isOutboundDone(); }
		public String[] getSupportedCipherSuites() { return e.getSupportedCipherSuites(); }
		public String[] getEnabledCipherSuites() { return e.getEnabledCipherSuites(); }
		public void setEnabledCipherSuites(String[] suites) { e.setEnabledCipherSuites(suites); }
		public String[] getSupportedProtocols() { return e.getSupportedProtocols(); }
		public String[] getEnabledProtocols() { return e.getEnabledProtocols(); }
		public void setEnabledProtocols(String[] protocols) { e.setEnabledProtocols(protocols); }
		public void beginHandshake() throws SSLException { e.beginHandshake(); }
		public SSLEngineResult.HandshakeStatus getHandshakeStatus() { return e.getHandshakeStatus(); }
		public void setUseClientMode(boolean mode) { e.setUseClientMode(mode); }
		public boolean getUseClientMode() { return e.getUseClientMode(); }
		public void setNeedClientAuth(boolean need) { e.setNeedClientAuth(need); }
		public boolean getNeedClientAuth() { return e.getNeedClientAuth(); }
		public void setWantClientAuth(boolean want) { e.setWantClientAuth(want); }
		public boolean getWantClientAuth() { return e.getWantClientAuth(); }
		public void setEnableSessionCreation(boolean flag) { e.setEnableSessionCreation(flag); }
		public boolean getEnableSessionCreation() { return e.getEnableSessionCreation(); }
	}

	private String handshakeAndRead(int sessionBufferSize, int overflows) throws Exception {
		startServer();
		final SSLEngine real = clientContext().createSSLEngine(HOST, 443);
		real.setUseClientMode(true);
		real.setEnabledProtocols(new String[] { "TLSv1.2" });
		final QuirkyEngine engine = new QuirkyEngine(real, sessionBufferSize, overflows);
		final Socket raw = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
		raw.setSoTimeout(10000);
		try {
			final SSLEngineManager m = new SSLEngineManager(engine, new HandshakeCallbackHandler() {
				public void handshakeCompleted() {}
			}, raw.getInputStream(), raw.getOutputStream(), HOST);
			m.startHandshake();
			final byte[] b = new byte[2];
			int n = 0;
			while(n < 2) {
				final int r = m.read(b, n, 2 - n);
				assertTrue("end of stream", r > 0);
				n += r;
			}
			return new String(b, "US-ASCII");
		} finally {
			raw.close();
		}
	}

	@Test(timeout = 30000)
	public void testOverflowInTheHandshakeIsNotAnEnd() throws Exception {
		assertEquals("ok", handshakeAndRead(0, 2));
	}

	@Test(timeout = 30000)
	public void testSmallBuffersFromTheUnnegotiatedSessionGrow() throws Exception {
		// 512 bytes: smaller than the server's certificate record.
		assertEquals("ok", handshakeAndRead(512, 0));
	}

	@Test(timeout = 30000)
	public void testServerThatSaysNothingIsDescribed() throws Exception {
		final SSLEngine real = clientContext().createSSLEngine(HOST, 443);
		real.setUseClientMode(true);
		final java.io.ByteArrayOutputStream sink = new java.io.ByteArrayOutputStream();
		final InputStream nothing = new ByteArrayInputStream(new byte[0]);
		final SSLEngineManager m = new SSLEngineManager(real, new HandshakeCallbackHandler() {
			public void handshakeCompleted() {}
		}, nothing, sink, HOST);
		try {
			m.startHandshake();
			org.junit.Assert.fail("handshake completed without a server");
		} catch(javax.net.ssl.SSLHandshakeException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("before the server sent anything"));
		}
		// The ClientHello was sent.
		assertTrue(sink.size() > 0);
	}
}
