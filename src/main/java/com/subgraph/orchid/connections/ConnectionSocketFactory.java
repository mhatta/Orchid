package com.subgraph.orchid.connections;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.subgraph.orchid.TorException;

public class ConnectionSocketFactory {
    /*
     * The cipher suites Orchid offers to relays, in order of preference:
     * TLS 1.3, then TLS 1.2 suites with forward secrecy (ECDHE) and AEAD
     * encryption, then ECDHE with CBC as a last resort.  Relays have RSA link
     * keys, so the ECDHE_RSA suites are the ones that matter for TLS 1.2.
     *
     * Only the suites that the runtime supports are enabled
     * (chooseCipherSuites()).  Orchid used to pass a fixed list of 42 names
     * taken from OpenJDK 11, among them DHE, static ECDH and DSS suites.
     * Android's TLS provider (Conscrypt / BoringSSL) supports none of those
     * and rejects the whole list with an IllegalArgumentException when one
     * name is unknown, so no relay could be reached on Android.  The list
     * also left out the TLS 1.3 suites, which turned TLS 1.3 off.
     */
    static final String[] PREFERRED_CIPHER_SUITES = {
        // TLS 1.3
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        // TLS 1.2, ECDHE + AEAD
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        // TLS 1.2, ECDHE + CBC
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    };

    /* TLS versions Orchid offers to relays, newest first. */
    static final String[] PREFERRED_PROTOCOLS = { "TLSv1.3", "TLSv1.2" };

    /**
     * The entries of <code>preferred</code> that are in <code>supported</code>,
     * in the order of <code>preferred</code>.
     */
    static String[] intersect(String[] preferred, String[] supported) {
        final java.util.Set<String> available = new java.util.HashSet<String>(java.util.Arrays.asList(supported));
        final java.util.List<String> result = new java.util.ArrayList<String>();
        for(String name: preferred) {
            if(available.contains(name)) {
                result.add(name);
            }
        }
        return result.toArray(new String[result.size()]);
    }

    /**
     * The cipher suites to enable, chosen from the ones the TLS provider
     * supports.
     *
     * @throws TorException if the provider supports none of them.
     */
    static String[] chooseCipherSuites(String[] supported) {
        final String[] suites = intersect(PREFERRED_CIPHER_SUITES, supported);
        if(suites.length == 0) {
            throw new TorException("The TLS provider supports none of the cipher suites Orchid uses with relays "
                    + java.util.Arrays.toString(PREFERRED_CIPHER_SUITES));
        }
        return suites;
    }

    /**
     * The TLS versions to enable, chosen from the ones the TLS provider
     * supports.
     *
     * @throws TorException if the provider supports neither TLS 1.3 nor 1.2.
     */
    static String[] chooseProtocols(String[] supported) {
        final String[] protocols = intersect(PREFERRED_PROTOCOLS, supported);
        if(protocols.length == 0) {
            throw new TorException("The TLS provider supports neither TLS 1.3 nor TLS 1.2");
        }
        return protocols;
    }

	private static final TrustManager[] NULL_TRUST = {
		new X509TrustManager() {
			private final X509Certificate[] empty = {};
			public void checkClientTrusted(X509Certificate[] chain, String authType)
					throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType)
					throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return empty;
			}
		}
	};
	
	private static SSLContext createSSLContext() {
		/*
		 * Orchid used to set sun.security.ssl.allowUnsafeRenegotiation=true
		 * here, for the renegotiation based link handshakes of link protocols
		 * 1 and 2.  Only link protocols 4 and 5 (in-protocol handshake, no
		 * renegotiation) are spoken now, and the property applied to every TLS
		 * connection of the JVM Orchid runs in, so it is no longer set.
		 */
		try {
			final SSLContext sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, NULL_TRUST, null);
			return sslContext;
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		} catch (KeyManagementException e) {
			throw new TorException(e);
		}
	}
	
	private final SSLSocketFactory socketFactory;
	private final String[] cipherSuites;
	private final String[] protocols;
	
	ConnectionSocketFactory() {
		this(createSSLContext().getSocketFactory());
	}

	/* For tests: any SSLSocketFactory, e.g. one that behaves like Conscrypt. */
	ConnectionSocketFactory(SSLSocketFactory socketFactory) {
		this.socketFactory = socketFactory;
		this.cipherSuites = chooseCipherSuites(socketFactory.getSupportedCipherSuites());
		this.protocols = chooseProtocols(probeSupportedProtocols(socketFactory));
	}

	/*
	 * SSLSocketFactory has no getSupportedProtocols(); ask an unconnected
	 * socket.
	 */
	private static String[] probeSupportedProtocols(SSLSocketFactory factory) {
		try {
			final SSLSocket probe = (SSLSocket) factory.createSocket();
			try {
				return probe.getSupportedProtocols();
			} finally {
				probe.close();
			}
		} catch (IOException e) {
			throw new TorException(e);
		}
	}
	
	SSLSocket createSocket() {
		try {
			final SSLSocket socket = (SSLSocket) socketFactory.createSocket();
			socket.setEnabledProtocols(protocols);
			socket.setEnabledCipherSuites(cipherSuites);
			socket.setUseClientMode(true);
			return socket;
		} catch (IOException e) {
			throw new TorException(e);
		}
	}

	String[] getEnabledCipherSuites() {
		return cipherSuites.clone();
	}

	String[] getEnabledProtocols() {
		return protocols.clone();
	}
}
