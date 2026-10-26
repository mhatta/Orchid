package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.After;
import org.junit.Assume;
import org.junit.Test;

import com.subgraph.orchid.TorException;

/**
 * The cipher suites and TLS versions offered to relays are chosen from the
 * ones the TLS provider supports, so that the list works with Android's
 * Conscrypt as well as with the JDK.
 */
public class ConnectionSocketFactoryTest {
	/*
	 * The cipher suites Conscrypt supports, from its CAPABILITIES.md
	 * (https://github.com/google/conscrypt/blob/master/CAPABILITIES.md).
	 * Conscrypt rejects the whole list given to setEnabledCipherSuites()
	 * with an IllegalArgumentException when it contains any other name.
	 */
	static final Set<String> CONSCRYPT_SUPPORTED = new HashSet<String>(Arrays.asList(
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"SSL_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_PSK_WITH_AES_128_CBC_SHA",
		"TLS_PSK_WITH_AES_256_CBC_SHA"));

	/* Some of the names of the fixed list Orchid passed up to 2.1.2. */
	static final String[] OLD_LIST_SAMPLE = {
		"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	};

	/*
	 * A self-signed 1024 bit RSA certificate, as relays use for their link
	 * keys, valid until 2126 (PKCS#12 with legacy encryption).
	 */
	final static String RELAY_KEYSTORE_BASE64 =
		"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" +
		"mrIbU2ssmCjJ2AIDAYag";

	private SSLServerSocket server;

	@After
	public void after() throws IOException {
		if(server != null) {
			server.close();
		}
	}

	@Test
	public void testConscryptAcceptsEverySuiteChosen() {
		final String[] chosen = ConnectionSocketFactory.chooseCipherSuites(
				CONSCRYPT_SUPPORTED.toArray(new String[0]));
		for(String suite: chosen) {
			assertTrue(suite +" is not supported by Conscrypt", CONSCRYPT_SUPPORTED.contains(suite));
		}
		final List<String> c = Arrays.asList(chosen);
		assertTrue(c.contains("TLS_AES_128_GCM_SHA256"));
		assertTrue(c.contains("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
	}

	@Test
	public void testOldFixedListWasRejectedByConscrypt() {
		// Why Orchid could not connect on Android: each of these makes Conscrypt throw.
		for(String suite: OLD_LIST_SAMPLE) {
			assertFalse(suite, CONSCRYPT_SUPPORTED.contains(suite));
		}
	}

	@Test
	public void testOrderFollowsPreference() {
		final String[] chosen = ConnectionSocketFactory.chooseCipherSuites(new String[] {
				"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" });
		assertArrayEquals(new String[] { "TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" }, chosen);
	}

	@Test
	public void testNoUsableSuite() {
		try {
			ConnectionSocketFactory.chooseCipherSuites(new String[] { "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" });
			fail("expected TorException");
		} catch(TorException expected) {
		}
	}

	@Test
	public void testProtocols() {
		assertArrayEquals(new String[] { "TLSv1.3", "TLSv1.2" },
				ConnectionSocketFactory.chooseProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" }));
		assertArrayEquals(new String[] { "TLSv1.2" },
				ConnectionSocketFactory.chooseProtocols(new String[] { "SSLv3", "TLSv1", "TLSv1.2" }));
		try {
			ConnectionSocketFactory.chooseProtocols(new String[] { "TLSv1", "TLSv1.1" });
			fail("expected TorException");
		} catch(TorException expected) {
		}
	}

	@Test
	public void testJdkSuitesAreAllUsable() {
		// Every suite chosen on this JDK is one the JDK can enable.
		final ConnectionSocketFactory f = new ConnectionSocketFactory();
		final SSLSocket s = f.createSocket();
		assertEquals(new HashSet<String>(Arrays.asList(f.getEnabledCipherSuites())),
				new HashSet<String>(Arrays.asList(s.getEnabledCipherSuites())));
		assertTrue(Arrays.asList(s.getEnabledProtocols()).contains("TLSv1.2"));
	}

	private void startRelayLikeServer(String... protocols) throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(RELAY_KEYSTORE_BASE64)), "orchid".toCharArray());
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, "orchid".toCharArray());
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
		server.setEnabledProtocols(protocols);
		final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					final SSLSocket s = (SSLSocket) server.accept();
					s.startHandshake();
					s.getOutputStream().write(1);
					s.getOutputStream().flush();
					s.getInputStream().read();
					s.close();
				} catch(Exception e) {
					failure.set(e);
				}
			}
		});
		t.setDaemon(true);
		t.start();
	}

	private SSLSocket handshake() throws IOException {
		final SSLSocket s = new ConnectionSocketFactory().createSocket();
		s.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getLocalPort()), 5000);
		s.setSoTimeout(5000);
		s.startHandshake();
		assertEquals(1, s.getInputStream().read());
		return s;
	}

	@Test(timeout = 20000)
	public void testHandshakeWithRelayLikeServerTls13() throws Exception {
		Assume.assumeTrue(Arrays.asList(SSLContext.getDefault().getSupportedSSLParameters().getProtocols()).contains("TLSv1.3"));
		startRelayLikeServer("TLSv1.3");
		final SSLSocket s = handshake();
		try {
			assertEquals("TLSv1.3", s.getSession().getProtocol());
			assertTrue(Arrays.asList(ConnectionSocketFactory.PREFERRED_CIPHER_SUITES).contains(s.getSession().getCipherSuite()));
			// What ConnectionHandshakeV3 needs from the session: the relay's link certificate
			assertTrue(ConnectionHandshakeV3.sessionSupportsHandshake(s.getSession()));
		} finally {
			s.close();
		}
	}

	@Test(timeout = 20000)
	public void testHandshakeWithRelayLikeServerTls12() throws Exception {
		startRelayLikeServer("TLSv1.2");
		final SSLSocket s = handshake();
		try {
			assertEquals("TLSv1.2", s.getSession().getProtocol());
			assertTrue(s.getSession().getCipherSuite(), s.getSession().getCipherSuite().startsWith("TLS_ECDHE_RSA_"));
		} finally {
			s.close();
		}
	}
}
