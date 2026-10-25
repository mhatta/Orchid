package com.subgraph.orchid.sockets.sslengine;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.junit.After;
import org.junit.Assume;
import org.junit.Test;

/**
 * SSLEngineSSLSocket against a local JSSE server.
 *
 * TLS 1.3 servers send NewSessionTicket messages after the handshake;
 * records without application data used to be taken for the end of the
 * stream, so no data could be read over TLS 1.3 at all.  Also checks that
 * records already received are delivered while the connection stays open,
 * and the host name check of the four argument constructor.
 */
public class SSLEngineSSLSocketTest {
	private final static String HOST = "test.orchid.invalid";
	private final static char[] PASSWORD = "orchid".toCharArray();

	/*
	 * A self-signed RSA certificate for test.orchid.invalid, valid until
	 * 2126, with its key (PKCS#12, legacy encryption so that older JDKs can
	 * read it).  Made with:
	 *   keytool -J-Dkeystore.pkcs12.legacy -genkeypair -alias test -keyalg RSA
	 *     -keysize 2048 -dname CN=test.orchid.invalid
	 *     -ext SAN=dns:test.orchid.invalid -validity 36500 -storetype PKCS12
	 */
	private final static String KEYSTORE_BASE64 =
		"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" +
		"HooEFD899k2MaKG4Mz/yzE0c2x1CTa4oAgMBhqA=";

	private interface ServerBehaviour {
		void serve(SSLSocket socket) throws IOException;
	}

	private SSLServerSocket server;
	private final AtomicReference<Throwable> serverFailure = new AtomicReference<Throwable>();

	@After
	public void after() throws IOException {
		if(server != null) {
			server.close();
		}
	}

	private static KeyStore keyStore() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(KEYSTORE_BASE64)), PASSWORD);
		return ks;
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

	private static void assumeProtocol(String protocol) throws Exception {
		Assume.assumeTrue(protocol +" not supported by this JDK",
				Arrays.asList(SSLContext.getDefault().getSupportedSSLParameters().getProtocols()).contains(protocol));
	}

	private void startServer(String protocol, final ServerBehaviour behaviour) throws Exception {
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore(), PASSWORD);
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
		server.setEnabledProtocols(new String[] { protocol });
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					final SSLSocket s = (SSLSocket) server.accept();
					try {
						behaviour.serve(s);
					} finally {
						s.close();
					}
				} catch(IOException e) {
					if(!server.isClosed()) {
						serverFailure.set(e);
					}
				} catch(Throwable e) {
					serverFailure.set(e);
				}
			}
		});
		t.setDaemon(true);
		t.start();
	}

	private SSLEngineSSLSocket connect(String host) throws Exception {
		final Socket raw = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
		raw.setSoTimeout(10000);
		return new SSLEngineSSLSocket(raw, clientContext(), host, 443);
	}

	private static byte[] readFully(InputStream in, int n) throws IOException {
		final byte[] b = new byte[n];
		int off = 0;
		while(off < n) {
			final int r = in.read(b, off, n - off);
			if(r < 0) {
				fail("end of stream after "+ off +" of "+ n +" bytes");
			}
			off += r;
		}
		return b;
	}

	private static byte[] readToEof(InputStream in) throws IOException {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] b = new byte[1000];
		int r;
		while((r = in.read(b)) >= 0) {
			out.write(b, 0, r);
		}
		return out.toByteArray();
	}

	/* The server answers "ping" with "pong" and keeps the connection open. */
	private void checkRequestReply(String protocol) throws Exception {
		assumeProtocol(protocol);
		startServer(protocol, new ServerBehaviour() {
			public void serve(SSLSocket s) throws IOException {
				final byte[] request = readFully(s.getInputStream(), 4);
				assertArrayEquals("ping".getBytes("US-ASCII"), request);
				s.getOutputStream().write("pong".getBytes("US-ASCII"));
				s.getOutputStream().flush();
				// keep the connection open until the client has read the reply
				s.getInputStream().read();
			}
		});
		final SSLEngineSSLSocket s = connect(HOST);
		try {
			s.getOutputStream().write("ping".getBytes("US-ASCII"));
			s.getOutputStream().flush();
			assertArrayEquals("pong".getBytes("US-ASCII"), readFully(s.getInputStream(), 4));
			assertEquals(protocol, s.getSession().getProtocol());
		} finally {
			s.close();
		}
		assertTrue(String.valueOf(serverFailure.get()), serverFailure.get() == null);
	}

	/* The server sends a large reply in many records and closes. */
	private void checkLargeReply(String protocol) throws Exception {
		assumeProtocol(protocol);
		final byte[] data = new byte[300 * 1024];
		for(int i = 0; i < data.length; i++) {
			data[i] = (byte) (i * 31 + (i >> 8));
		}
		startServer(protocol, new ServerBehaviour() {
			public void serve(SSLSocket s) throws IOException {
				readFully(s.getInputStream(), 1);
				final OutputStream out = s.getOutputStream();
				// small and odd sized writes, so that records straddle reads
				for(int off = 0; off < data.length; off += 777) {
					out.write(data, off, Math.min(777, data.length - off));
				}
				out.flush();
			}
		});
		final SSLEngineSSLSocket s = connect(HOST);
		try {
			s.getOutputStream().write('x');
			s.getOutputStream().flush();
			assertArrayEquals(data, readToEof(s.getInputStream()));
		} finally {
			s.close();
		}
	}

	@Test(timeout = 30000)
	public void testRequestReplyTls13() throws Exception {
		checkRequestReply("TLSv1.3");
	}

	@Test(timeout = 30000)
	public void testRequestReplyTls12() throws Exception {
		checkRequestReply("TLSv1.2");
	}

	@Test(timeout = 30000)
	public void testLargeReplyTls13() throws Exception {
		checkLargeReply("TLSv1.3");
	}

	@Test(timeout = 30000)
	public void testLargeReplyTls12() throws Exception {
		checkLargeReply("TLSv1.2");
	}

	@Test(timeout = 30000)
	public void testCertificateForAnotherNameIsRefused() throws Exception {
		startServer("TLSv1.2", new ServerBehaviour() {
			public void serve(SSLSocket s) throws IOException {
				try {
					s.startHandshake();
				} catch(SSLException expected) {
					// the client refuses the certificate
				}
			}
		});
		final SSLEngineSSLSocket s = connect("www.example.com");
		try {
			s.startHandshake();
			fail("a certificate for "+ HOST +" was accepted for www.example.com");
		} catch(SSLException expected) {
			// No subject alternative DNS name matching www.example.com
		} finally {
			s.close();
		}
	}
}
