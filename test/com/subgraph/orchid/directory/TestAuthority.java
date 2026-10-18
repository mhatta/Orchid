package com.subgraph.orchid.directory;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.crypto.RSAKeyEncoder;
import com.subgraph.orchid.crypto.TorPrivateKey;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.encoders.Base64;

/**
 * A directory authority with freshly generated keys, able to write key
 * certificates in the dir-spec 3.1 format.  For tests only.
 */
public class TestAuthority {
	private static final Charset ASCII = Charset.forName("ISO-8859-1");
	private static final long HOUR = 60 * 60 * 1000L;

	private final TorPrivateKey identityKey = TorPrivateKey.generateNewKeypair();

	public HexDigest getFingerprint() {
		return identityKey.getPublicKey().getFingerprint();
	}

	public TorPrivateKey newSigningKey() {
		return TorPrivateKey.generateNewKeypair();
	}

	/** A certificate for signingKey published the given number of hours ago. */
	public String certificate(TorPrivateKey signingKey, int publishedHoursAgo) {
		return certificate(getFingerprint(), signingKey, publishedHoursAgo, identityKey);
	}

	/**
	 * A certificate that claims declaredFingerprint and is certified by
	 * certifyingKey, which need not be this authority's identity key.
	 */
	public String certificate(HexDigest declaredFingerprint, TorPrivateKey signingKey, int publishedHoursAgo, TorPrivateKey certifyingKey) {
		final Date now = new Date();
		final StringBuilder sb = new StringBuilder();
		sb.append("dir-key-certificate-version 3\n");
		sb.append("dir-address 192.0.2.1:80\n");
		sb.append("fingerprint ").append(declaredFingerprint.toString().toUpperCase()).append('\n');
		sb.append("dir-key-published ").append(format(new Date(now.getTime() - publishedHoursAgo * HOUR))).append('\n');
		sb.append("dir-key-expires ").append(format(new Date(now.getTime() + 90 * 24 * HOUR))).append('\n');
		sb.append("dir-identity-key\n").append(pem(identityKey.getPublicKey()));
		sb.append("dir-signing-key\n").append(pem(signingKey.getPublicKey()));
		sb.append("dir-key-crosscert\n");
		sb.append(object("ID SIGNATURE", sign(signingKey.getRSAPrivateKey(), identityKey.getPublicKey().getFingerprint().getRawBytes())));
		sb.append("dir-key-certification\n");
		sb.append(object("SIGNATURE", sign(certifyingKey.getRSAPrivateKey(), sha1(sb.toString()))));
		return sb.toString();
	}

	public TorPrivateKey getIdentityKey() {
		return identityKey;
	}

	public static BasicDocumentParsingResult<KeyCertificate> parseCertificates(String text) {
		final BasicDocumentParsingResult<KeyCertificate> result = new BasicDocumentParsingResult<KeyCertificate>();
		new DocumentParserFactoryImpl().createKeyCertificateParser(ByteBuffer.wrap(text.getBytes(ASCII))).parse(result);
		return result;
	}

	public static KeyCertificate parseCertificate(String text) {
		final List<KeyCertificate> certs = parseCertificates(text).getParsedDocuments();
		if(certs.size() != 1) {
			throw new IllegalStateException("expected one certificate, got "+ certs.size());
		}
		return certs.get(0);
	}

	private static String format(Date d) {
		final SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		f.setTimeZone(TimeZone.getTimeZone("UTC"));
		return f.format(d);
	}

	private static String pem(TorPublicKey key) {
		return object("RSA PUBLIC KEY", new RSAKeyEncoder().getPKCS1Encoded(key.getRSAPublicKey()));
	}

	private static String object(String type, byte[] data) {
		final String b64 = new String(Base64.encode(data), ASCII);
		final StringBuilder sb = new StringBuilder("-----BEGIN ").append(type).append("-----\n");
		for(int i = 0; i < b64.length(); i += 64) {
			sb.append(b64, i, Math.min(b64.length(), i + 64)).append('\n');
		}
		return sb.append("-----END ").append(type).append("-----\n").toString();
	}

	/* Tor directory signatures: PKCS#1 v1.5 padding over the raw digest. */
	private static byte[] sign(RSAPrivateKey key, byte[] digest) {
		try {
			final Signature s = Signature.getInstance("NONEwithRSA");
			s.initSign(key);
			s.update(digest);
			return s.sign();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private static byte[] sha1(String text) {
		try {
			return MessageDigest.getInstance("SHA-1").digest(text.getBytes(ASCII));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}
}
