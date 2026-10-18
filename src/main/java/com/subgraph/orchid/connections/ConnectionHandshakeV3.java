package com.subgraph.orchid.connections;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionIOException;

public class ConnectionHandshakeV3 extends ConnectionHandshake {

    private X509Certificate linkCertificate, identityCertificate, signing, tls, cross;
	
	ConnectionHandshakeV3(ConnectionImpl connection, SSLSocket socket) {
		super(connection, socket);
	}

	void runHandshake() throws IOException, InterruptedException, ConnectionIOException {
		sendVersions(3);
		receiveVersions();
		recvCerts();
		recvAuthChallengeAndNetinfo();
		verifyCertificates();
		sendNetinfo();
	}
	
	void recvCerts() throws ConnectionHandshakeException  {
		final Cell cell = expectCell(Cell.CERTS);
		final int ncerts = cell.getByte();
		if(ncerts != 2 && ncerts != 5) {
			throw new ConnectionHandshakeException("Expecting 2 or 5 certificates and got "+ ncerts);
		}

		linkCertificate = null;
		identityCertificate = null;
		signing = null;
		tls = null;
		cross = null;
		
		for(int i = 0; i < ncerts; i++) {
			int type = cell.getByte();
			if(type == 1) {
				linkCertificate = testAndReadCertificate(cell, linkCertificate, "Link (type = 1)");
			} else if(type == 2) {
				identityCertificate = testAndReadCertificate(cell, identityCertificate, "Identity (type = 2)");
			} else if(type == 4) {
			        signing = testAndReadCertificate(cell, signing, "Ed25519 signing key (type = 4)");
			} else if(type == 5) {
			        tls = testAndReadCertificate(cell, tls, "TLS Link certificate (type = 5)");
			} else if(type == 7) {
			        cross = testAndReadCertificate(cell, cross, "RSA Identity cross verification (type = 7)");
			} else {
				throw new ConnectionHandshakeException("Unexpected certificate type = "+ type + " in CERTS cell");
			}
		}
		
	}
	
	RSAPublicKey getConnectionPublicKey() {
		final X509Certificate cert = getConnectionCertificateFromSession(socket.getSession());
		if(cert == null || !(cert.getPublicKey() instanceof RSAPublicKey)) {
			return null;
		}
		return (RSAPublicKey) cert.getPublicKey();
	}
	

	private X509Certificate testAndReadCertificate(Cell cell, X509Certificate currentValue, String type) throws ConnectionHandshakeException {
		if(currentValue == null) {
			return readCertificateFromCell(cell);
		} else {
			throw new ConnectionHandshakeException("Duplicate "+ type + " certificates in CERTS cell");
		}
	}
	
	private X509Certificate readCertificateFromCell(Cell cell) {
		try {
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			final int clen = cell.getShort();
			final byte[] certificateBuffer = new byte[clen];
			cell.getByteArray(certificateBuffer);
			final ByteArrayInputStream bis = new ByteArrayInputStream(certificateBuffer);
			return (X509Certificate) certificateFactory.generateCertificate(bis);
		} catch (CertificateException e) {
			return null;
		}
		
	}
	
	void verifyCertificates() throws ConnectionHandshakeException {
		PublicKey publicKey = identityCertificate.getPublicKey();
		verifyIdentityKey(publicKey);
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		
		if(rsaPublicKey.getModulus().bitLength() != 1024) {
			throw new ConnectionHandshakeException("Invalid RSA modulus length in router identity key");
		}
		
		try {
			identityCertificate.checkValidity();
			identityCertificate.verify(rsaPublicKey);
			linkCertificate.checkValidity();
			linkCertificate.verify(rsaPublicKey);
		} catch (GeneralSecurityException e) {
			throw new ConnectionHandshakeException("Router presented invalid certificate chain in CERTS cell");
		}
	
		RSAPublicKey rsa2 = (RSAPublicKey) linkCertificate.getPublicKey();
		if(!getConnectionPublicKey().getModulus().equals(rsa2.getModulus())) {
			throw new ConnectionHandshakeException("Link certificate in CERTS cell does not match connection certificate");
		}
	}

	void recvAuthChallengeAndNetinfo() throws ConnectionHandshakeException {
		final Cell cell = expectCell(Cell.AUTH_CHALLENGE, Cell.NETINFO);
		if(cell.getCommand() == Cell.NETINFO) {
			processNetInfo(cell);
			return;
		}
		final Cell netinfo = expectCell(Cell.NETINFO);
		processNetInfo(netinfo);
	}
	
	public static boolean sessionSupportsHandshake(SSLSession session) {
		final X509Certificate cert = getConnectionCertificateFromSession(session);
		if(cert == null) {
			return false;
		}
		return isSelfSigned(cert) || testDName(cert.getSubjectX500Principal()) ||
				testDName(cert.getIssuerX500Principal()) || testModulusLength(cert); 
	}
	
	/*
	 * SSLSession.getPeerCertificateChain() (javax.security.cert) is deprecated
	 * and throws UnsupportedOperationException since JDK 15, so the
	 * java.security.cert API is used instead.
	 */
	static private X509Certificate getConnectionCertificateFromSession(SSLSession session) {
		try {
			final java.security.cert.Certificate[] chain = session.getPeerCertificates();
			if(chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
				return null;
			}
			return (X509Certificate) chain[0];
		} catch (SSLPeerUnverifiedException e) {
			return null;
		}
	}
	
	static private boolean isSelfSigned(X509Certificate certificate) {
		try {
			certificate.verify(certificate.getPublicKey());
			return true;
		} catch (Exception e) {
			return false;
		}
	}
	
    /*
     * * Some component other than "commonName" is set in the subject or
     *   issuer DN of the certificate.
     *   
     * * The commonName of the subject or issuer of the certificate ends
     *   with a suffix other than ".net".
     */
	static private boolean testDName(Principal dn) {
		final String dname = dn.getName();
		if(dname.indexOf(",") >= 0) {
			return true;
		}
		return !getCN(dname).endsWith(".net");
	}

	/*
	 * * The certificate's public key modulus is longer than 1024 bits.
	 */
	static private boolean testModulusLength(X509Certificate cert) {
		if(!(cert.getPublicKey() instanceof RSAPublicKey)) {
			return false;
		}
		final RSAPublicKey rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
		final BigInteger modulus = rsaPublicKey.getModulus();
		return modulus.bitLength() > 1024;
	}

	static private String getCN(String dname) {
		final int idx = dname.indexOf("CN=");
		if(idx == -1) {
			return "";
		}
		final int comma = dname.indexOf(',', idx);
		if(comma == -1) {
			return dname.substring(idx);
		} else {
			return dname.substring(idx, comma);
		}
	}
}
