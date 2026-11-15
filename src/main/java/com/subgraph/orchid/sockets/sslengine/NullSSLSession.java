package com.subgraph.orchid.sockets.sslengine;

import java.security.Principal;
import java.security.cert.Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * The session of a socket whose handshake failed, as JSSE's sockets return
 * it from getSession(): not valid, cipher suite SSL_NULL_WITH_NULL_NULL,
 * protocol NONE, and no peer.  Code that checks isValid() or the peer's
 * certificates after a failed host name check sees a failure, not the
 * session the rejected server set up.
 */
final class NullSSLSession implements SSLSession {
	static final NullSSLSession INSTANCE = new NullSSLSession();

	static final String CIPHER_SUITE = "SSL_NULL_WITH_NULL_NULL";
	static final String PROTOCOL = "NONE";

	private NullSSLSession() {}

	public byte[] getId() {
		return new byte[0];
	}

	public SSLSessionContext getSessionContext() {
		return null;
	}

	public long getCreationTime() {
		return 0;
	}

	public long getLastAccessedTime() {
		return 0;
	}

	public void invalidate() {
	}

	public boolean isValid() {
		return false;
	}

	public void putValue(String name, Object value) {
	}

	public Object getValue(String name) {
		return null;
	}

	public void removeValue(String name) {
	}

	public String[] getValueNames() {
		return new String[0];
	}

	public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
		throw new SSLPeerUnverifiedException("TLS handshake failed");
	}

	public Certificate[] getLocalCertificates() {
		return null;
	}

	@SuppressWarnings("deprecation")
	public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
		throw new SSLPeerUnverifiedException("TLS handshake failed");
	}

	public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
		throw new SSLPeerUnverifiedException("TLS handshake failed");
	}

	public Principal getLocalPrincipal() {
		return null;
	}

	public String getCipherSuite() {
		return CIPHER_SUITE;
	}

	public String getProtocol() {
		return PROTOCOL;
	}

	public String getPeerHost() {
		return null;
	}

	public int getPeerPort() {
		return -1;
	}

	public int getPacketBufferSize() {
		return 16709;
	}

	public int getApplicationBufferSize() {
		return 16384;
	}

	@Override
	public String toString() {
		return "[Session: failed handshake, "+ CIPHER_SUITE +"]";
	}
}
