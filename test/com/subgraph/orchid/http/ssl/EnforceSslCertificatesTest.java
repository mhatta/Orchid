package com.subgraph.orchid.http.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.sockets.sslengine.SSLEngineSSLSocket;

/**
 * Additional certificates are trusted besides the platform's trust store,
 * without reading the JDK's cacerts file (java.nio.file is not available
 * before Android API level 26), and the host name is still checked.
 */
public class EnforceSslCertificatesTest {
	private final static String HOST = "test.orchid.invalid";
	private final static char[] PASSWORD = "orchid".toCharArray();

	/*
	 * PKCS#12 key store (password "orchid") with a self-signed EC
	 * certificate for test.orchid.invalid, made with
	 *
	 *   keytool -J-Dkeystore.pkcs12.legacy -genkeypair -alias test -keyalg EC
	 *     -groupname secp256r1 -dname CN=test.orchid.invalid
	 *     -ext SAN=dns:test.orchid.invalid -validity 36500
	 *     -storetype PKCS12 -storepass orchid
	 */
	private final static String KEYSTORE_BASE64 =
		"MIIDfAIBAzCCAzUGCSqGSIb3DQEHAaCCAyYEggMiMIIDHjCB2wYJKoZIhvcNAQcBoIHNBIHK" +
		"MIHHMIHEBgsqhkiG9w0BDAoBAqB3MHUwKQYKKoZIhvcNAQwBAzAbBBRdKgQszftqd3C22g+D" +
		"xYXa4w42+AIDAMNQBEhzjkI9cFf6gUXocD77e5eCDxj3o+JdQLIw7nPuRnrSdiVX+VjHQ3Q7" +
		"nSNDDfmiffkTGr1bEgQBCk5IZhEXtUZl+YC4JA5B4TAxPDAXBgkqhkiG9w0BCRQxCh4IAHQA" +
		"ZQBzAHQwIQYJKoZIhvcNAQkVMRQEElRpbWUgMTc5MzIzNTQ2MDY4NDCCAjwGCSqGSIb3DQEH" +
		"BqCCAi0wggIpAgEAMIICIgYJKoZIhvcNAQcBMCkGCiqGSIb3DQEMAQYwGwQUfpgnxOC5GBaJ" +
		"lfJeNFUCe2k9EYQCAwDDUICCAej3qnNtN/R/gNL4adUKYNzSPr2eMuxuq8DPBVXUhZ9U7nG1" +
		"pr8JL0TYqycFEp05Ts6u6TCwpioiZJ3pJSeKji1TBeY0L8D3EhLJktYE3dR5zWM9vu12boQY" +
		"UIIehUD89466Sp8wqwHPB4FJDvKC4Bf+zzH4rw48ds6jxiTJ021d2MW8ao9MdrQL0enHD3c1" +
		"UL6i43zmKwy91Wsu+cCvlzaL6kp7YMa6dRg6LrS5HN1seKLDopCIUem8GIQurrx4XDjDP2ZQ" +
		"YktCiKGpndtLiEeAqge36irasMYSlKq2Lv8ISpZq0JlYElqCBpp3WDZ7WsYDMMKSQj4iGWLL" +
		"mWZ+VD5PA+S//adb9V9aooCW8PDLjwwv5MI2jdN660wCU2bQCs4/foJrOXQko5EZEfQOid0/" +
		"PLjYOa1De3WCM1YfO6kmSgrO7U11xYybJv9YPJi4By6niQKUqmILw0GoVSCZklFtQpsxFGtf" +
		"vrvqIwDX4MvF0tp6R4F6oLuvy9K8J67oaBdpLcpeCGhui+aM8Oyp2y5lWuoYvSnmlUsOFfvl" +
		"AMhDRvG6UGrhJtVDlyGTldgYTyWbLOmnojSyypu1BoTVBDOtBgSmd+Z7vgSh7WgKfzZPA49s" +
		"txYuLSOq93erR7xmcaK6QhdE9lkadzA+MCEwCQYFKw4DAhoFAAQUqVZOH1oKLK4CbMvsyc4f" +
		"GX75B84EFPTwXtnyUxi6ogqV2YO3mT7NlIb1AgMBhqA=";

	private SSLServerSocket server;

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

	private static X509Certificate certificate() throws Exception {
		return (X509Certificate) keyStore().getCertificate("test");
	}

	/* A TLS server with the test certificate that completes the handshake and closes. */
	private void startServer() throws Exception {
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(keyStore(), PASSWORD);
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
		final Thread t = new Thread(new Runnable() {
			public void run() {
				while(true) {
					try {
						final SSLSocket s = (SSLSocket) server.accept();
						try {
							s.startHandshake();
							s.getInputStream().read();
						} catch(IOException e) {
							// refused by the client
						} finally {
							s.close();
						}
					} catch(IOException e) {
						return;
					}
				}
			}
		});
		t.setDaemon(true);
		t.start();
	}

	private boolean handshake(SSLContext context, String host) throws Exception {
		final Socket raw = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort());
		raw.setSoTimeout(10000);
		final SSLEngineSSLSocket s = new SSLEngineSSLSocket(raw, context, host, 443);
		try {
			s.startHandshake();
			return s.getSession().getPeerCertificates().length > 0;
		} catch(IOException e) {
			return false;
		} finally {
			s.close();
		}
	}

	@Test
	public void testNoBundledCertificates() {
		assertEquals(0, ApplicationProperties.getAdditionalSslCertificates().length);
	}

	@Test
	public void testContextUsesPlatformTrustStore() throws Exception {
		final SSLContext before = SSLContext.getDefault();
		assertNotNull(EnforceSslCertificates.getSSLContext());
		// Creating Orchid's context must not replace the JVM wide default
		assertSame(before, SSLContext.getDefault());
	}

	@Test(timeout = 30000)
	public void testAdditionalCertificateIsTrusted() throws Exception {
		startServer();
		final SSLContext context = EnforceSslCertificates.createSSLContext(Arrays.asList(certificate()));
		assertTrue("the additional certificate was not trusted", handshake(context, HOST));
	}

	@Test(timeout = 30000)
	public void testHostNameIsCheckedForAdditionalCertificate() throws Exception {
		startServer();
		final SSLContext context = EnforceSslCertificates.createSSLContext(Arrays.asList(certificate()));
		if(handshake(context, "other.orchid.invalid")) {
			fail("a certificate for "+ HOST +" was accepted for other.orchid.invalid");
		}
	}

	@Test(timeout = 30000)
	public void testUnknownCertificateIsRefused() throws Exception {
		startServer();
		final SSLContext context = EnforceSslCertificates.createSSLContext(Collections.<X509Certificate>emptyList());
		if(handshake(context, HOST)) {
			fail("a self-signed certificate was accepted without being configured");
		}
	}

	@Test
	public void testPlatformIssuersAreKept() throws Exception {
		final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init((KeyStore) null);
		final X509ExtendedTrustManager platform = (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
		final KeyStore extra = KeyStore.getInstance(KeyStore.getDefaultType());
		extra.load(null, null);
		extra.setCertificateEntry("test", certificate());
		tmf.init(extra);
		final X509TrustManager combined = new EnforceSslCertificates.CombinedTrustManager(platform, (X509ExtendedTrustManager) tmf.getTrustManagers()[0]);
		final List<X509Certificate> issuers = Arrays.asList(combined.getAcceptedIssuers());
		assertTrue(issuers.contains(certificate()));
		assertEquals(platform.getAcceptedIssuers().length + 1, issuers.size());
	}
}
