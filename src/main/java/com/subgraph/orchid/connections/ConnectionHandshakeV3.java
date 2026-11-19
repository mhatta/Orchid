package com.subgraph.orchid.connections;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
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
import com.subgraph.orchid.Router;

public class ConnectionHandshakeV3 extends ConnectionHandshake {

    private X509Certificate linkCertificate, identityCertificate;
    private CertsCell certs;
	
	ConnectionHandshakeV3(ConnectionImpl connection, SSLSocket socket) {
		super(connection, socket);
	}

	void runHandshake() throws IOException, InterruptedException, ConnectionIOException {
		sendVersions(SUPPORTED_LINK_VERSIONS);
		receiveVersions();
		recvCerts();
		recvAuthChallengeAndNetinfo();
		verifyCertificates();
		sendNetinfo();
	}
	
	void recvCerts() throws ConnectionHandshakeException  {
		certs = parseCertsCell(expectCell(Cell.CERTS));
		linkCertificate = certs.linkCertificate;
		identityCertificate = certs.identityCertificate;
	}

	/** CERT_TYPE values of the CERTS cell (cert-spec, "Certificate types"). */
	static final int CERT_TYPE_LINK = 1;
	static final int CERT_TYPE_RSA_IDENTITY = 2;
	static final int CERT_TYPE_ED25519_SIGNING = 4;
	static final int CERT_TYPE_ED25519_TLS_LINK = 5;
	static final int CERT_TYPE_RSA_ED25519_CROSSCERT = 7;

	/**
	 * The certificates of a CERTS cell.  Types 1 and 2 are X.509 and are
	 * parsed; types 4, 5 (Ed25519 certificates) and 7 (RSA to Ed25519 cross
	 * certificate) use Tor's own formats; they are kept as received and
	 * checked by {@link Ed25519LinkAuthentication}.
	 */
	static final class CertsCell {
		X509Certificate linkCertificate;
		X509Certificate identityCertificate;
		byte[] ed25519SigningCertificate;
		byte[] ed25519TlsLinkCertificate;
		byte[] rsaEd25519CrossCertificate;
	}

	/**
	 * Parse a CERTS cell.
	 *
	 * Only the X.509 certificates (types 1 and 2) go through the platform's
	 * CertificateFactory.  Types 4, 5 and 7 are not X.509, and relays send
	 * them on every connection; feeding them to the X.509 parser relied on
	 * it failing with a CertificateException, which other providers (such
	 * as Android's) need not do.  A malformed X.509 certificate or a length
	 * that runs past the end of the cell is a handshake error, not a null
	 * certificate or an unchecked exception later on.
	 *
	 * @throws ConnectionHandshakeException if the cell is malformed or lacks
	 *         the link or identity certificate.
	 */
	static CertsCell parseCertsCell(Cell cell) throws ConnectionHandshakeException {
		if(cell.cellBytesRemaining() < 1) {
			/* An empty CERTS cell ended in BufferUnderflowException (found by fuzzing). */
			throw new ConnectionHandshakeException("Empty CERTS cell");
		}
		final int ncerts = cell.getByte();
		if(ncerts != 2 && ncerts != 5) {
			throw new ConnectionHandshakeException("Expecting 2 or 5 certificates and got "+ ncerts);
		}
		final CertsCell certs = new CertsCell();
		final java.util.Set<Integer> seen = new java.util.HashSet<Integer>();
		for(int i = 0; i < ncerts; i++) {
			if(cell.cellBytesRemaining() < 3) {
				throw new ConnectionHandshakeException("Truncated CERTS cell");
			}
			final int type = cell.getByte();
			final int clen = cell.getShort();
			if(clen > cell.cellBytesRemaining()) {
				throw new ConnectionHandshakeException("Certificate of type "+ type +" runs past the end of the CERTS cell");
			}
			final byte[] body = new byte[clen];
			cell.getByteArray(body);
			if(!seen.add(type)) {
				throw new ConnectionHandshakeException("Duplicate certificates of type "+ type +" in CERTS cell");
			}
			switch(type) {
			case CERT_TYPE_LINK:
				certs.linkCertificate = parseX509(body, "link (type 1)");
				break;
			case CERT_TYPE_RSA_IDENTITY:
				certs.identityCertificate = parseX509(body, "identity (type 2)");
				break;
			case CERT_TYPE_ED25519_SIGNING:
				certs.ed25519SigningCertificate = body;
				break;
			case CERT_TYPE_ED25519_TLS_LINK:
				certs.ed25519TlsLinkCertificate = body;
				break;
			case CERT_TYPE_RSA_ED25519_CROSSCERT:
				certs.rsaEd25519CrossCertificate = body;
				break;
			default:
				throw new ConnectionHandshakeException("Unexpected certificate type = "+ type + " in CERTS cell");
			}
		}
		if(certs.linkCertificate == null || certs.identityCertificate == null) {
			throw new ConnectionHandshakeException("CERTS cell lacks the link (type 1) or identity (type 2) certificate");
		}
		return certs;
	}

	private static X509Certificate parseX509(byte[] encoded, String what) throws ConnectionHandshakeException {
		try {
			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
		} catch (CertificateException e) {
			throw new ConnectionHandshakeException("Malformed "+ what +" certificate in CERTS cell: "+ e.getMessage());
		} catch (RuntimeException e) {
			// Some providers throw unchecked exceptions on malformed input.
			throw new ConnectionHandshakeException("Malformed "+ what +" certificate in CERTS cell: "+ e);
		}
	}
	
	RSAPublicKey getConnectionPublicKey() {
		final X509Certificate cert = getConnectionCertificateFromSession(socket.getSession());
		if(cert == null || !(cert.getPublicKey() instanceof RSAPublicKey)) {
			return null;
		}
		return (RSAPublicKey) cert.getPublicKey();
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
		final RSAPublicKey connectionKey = getConnectionPublicKey();
		if(connectionKey == null || !connectionKey.getModulus().equals(rsa2.getModulus())) {
			throw new ConnectionHandshakeException("Link certificate in CERTS cell does not match connection certificate");
		}

		verifyEd25519Identity(rsaPublicKey);
	}

	/*
	 * tor-spec, "Validating a relay's CERTS cell": a relay that sends the
	 * Ed25519 certificates is authenticated by them as well, and its
	 * Ed25519 identity must be the one the directory lists for it.  A relay
	 * listed with an Ed25519 identity must send them: otherwise anyone who
	 * has (or has factored) the 1024 bit RSA identity key could pose as it.
	 * A router whose Ed25519 identity is not known (no descriptor yet, a
	 * fallback directory, a bridge without a descriptor) is authenticated
	 * by its RSA identity alone, as before.
	 */
	private void verifyEd25519Identity(RSAPublicKey rsaIdentity) throws ConnectionHandshakeException {
		final Router router = connection.getRouter();
		final byte[] expected = (router == null) ? null : router.getEd25519Identity();
		checkEd25519Identity(certs, expected, rsaIdentity,
				getConnectionCertificateEncoding(), System.currentTimeMillis() / 1000);
	}

	/**
	 * The Ed25519 part of the CERTS check, apart from the connection: the
	 * authenticated Ed25519 identity, or null if certs has no Ed25519
	 * certificates and expectedIdentity is null.
	 */
	static byte[] checkEd25519Identity(CertsCell certs, byte[] expectedIdentity, RSAPublicKey rsaIdentity,
			byte[] tlsCertificate, long nowSeconds) throws ConnectionHandshakeException {
		final boolean hasEdCerts = certs.ed25519SigningCertificate != null
				|| certs.ed25519TlsLinkCertificate != null || certs.rsaEd25519CrossCertificate != null;
		if(!hasEdCerts) {
			if(expectedIdentity != null) {
				throw new ConnectionHandshakeException("Router has an Ed25519 identity but sent no Ed25519 certificates");
			}
			return null;
		}
		final byte[] identity;
		try {
			identity = Ed25519LinkAuthentication.verify(certs.ed25519SigningCertificate,
					certs.ed25519TlsLinkCertificate, certs.rsaEd25519CrossCertificate, rsaIdentity,
					tlsCertificate, nowSeconds);
		} catch (RuntimeException e) {
			throw new ConnectionHandshakeException("Malformed Ed25519 certificates in CERTS cell: "+ e);
		}
		if(expectedIdentity != null && !MessageDigest.isEqual(expectedIdentity, identity)) {
			throw new ConnectionHandshakeException("Router Ed25519 identity does not match the Ed25519 certificates");
		}
		return identity;
	}

	private byte[] getConnectionCertificateEncoding() throws ConnectionHandshakeException {
		final X509Certificate cert = getConnectionCertificateFromSession(socket.getSession());
		if(cert == null) {
			return null;
		}
		try {
			return cert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ConnectionHandshakeException("Cannot encode the TLS certificate of the connection");
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
