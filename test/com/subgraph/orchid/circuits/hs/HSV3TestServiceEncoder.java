package com.subgraph.orchid.circuits.hs;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.subgraph.orchid.crypto.Curve25519;
import com.subgraph.orchid.crypto.Ed25519;
import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.crypto.Ed25519TestSigner;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.crypto.Keccak;
import com.subgraph.orchid.encoders.Base64;

/**
 * A minimal, test-only implementation of the <em>service</em> side of the v3
 * descriptor format, written independently from the client code (it uses the
 * JDK's AES/CTR and its own encoding helpers) so that the parser can be
 * exercised end to end: key blinding, certificates, both encryption layers,
 * client authorization and the outer signature.
 */
public class HSV3TestServiceEncoder {
	static final Charset ASCII = Charset.forName("ISO-8859-1");

	public final SecureRandom rng = new SecureRandom();
	public final Ed25519TestSigner identity;
	public final long periodNumber;
	public final long periodLength;
	public final byte[] blindingFactor;
	public final Ed25519TestSigner blinded;
	public final byte[] subcredential;
	public final Ed25519TestSigner descriptorSigning;
	public final long revisionCounter;
	public final long nowSeconds;
	public final List<IntroPoint> introPoints = new ArrayList<IntroPoint>();
	/* Client authorization: null means disabled */
	public byte[] clientAuthPublicKey;
	public byte[] clientAuthPrivateKey;
	public byte[] descriptorCookie;

	public static final class IntroPoint {
		public final byte[] legacyId = new byte[20];
		public final byte[] ed25519Id = new byte[32];
		public final byte[] ipv4 = new byte[4];
		public final int port;
		public final byte[] onionKey = new byte[32];
		public final Ed25519TestSigner authKey;
		public final byte[] encKeyPrivate;
		public final byte[] encKeyPublic = new byte[32];

		IntroPoint(SecureRandom rng, int port) {
			rng.nextBytes(legacyId);
			rng.nextBytes(ed25519Id);
			rng.nextBytes(ipv4);
			this.port = port;
			rng.nextBytes(onionKey);
			authKey = Ed25519TestSigner.random(rng);
			encKeyPrivate = new byte[32];
			rng.nextBytes(encKeyPrivate);
			encKeyPrivate[0] &= 248;
			encKeyPrivate[31] &= 127;
			encKeyPrivate[31] |= 64;
			Curve25519.crypto_scalarmult_base(encKeyPublic, encKeyPrivate);
		}
	}

	public HSV3TestServiceEncoder(long periodNumber, long periodLength, long nowSeconds, long revisionCounter) {
		this.identity = Ed25519TestSigner.random(rng);
		this.periodNumber = periodNumber;
		this.periodLength = periodLength;
		this.nowSeconds = nowSeconds;
		this.revisionCounter = revisionCounter;
		this.blindingFactor = Ed25519.clampScalar(HSV3Crypto.blindingParameter(identity.publicKey, periodNumber, periodLength));
		this.blinded = identity.blind(blindingFactor);
		this.subcredential = HSV3Crypto.subcredential(identity.publicKey, blinded.publicKey);
		this.descriptorSigning = Ed25519TestSigner.random(rng);
	}

	public String getOnionAddress() {
		return HSV3Address.encode(identity.publicKey) + ".onion";
	}

	public IntroPoint addIntroPoint(int port) {
		final IntroPoint ip = new IntroPoint(rng, port);
		introPoints.add(ip);
		return ip;
	}

	/** Enable client authorization for one client; returns the client's private key. */
	public byte[] enableClientAuth() {
		clientAuthPrivateKey = new byte[32];
		rng.nextBytes(clientAuthPrivateKey);
		clientAuthPrivateKey[0] &= 248;
		clientAuthPrivateKey[31] &= 127;
		clientAuthPrivateKey[31] |= 64;
		clientAuthPublicKey = new byte[32];
		Curve25519.crypto_scalarmult_base(clientAuthPublicKey, clientAuthPrivateKey);
		descriptorCookie = new byte[16];
		rng.nextBytes(descriptorCookie);
		return clientAuthPrivateKey.clone();
	}

	/* -------------------------------------------------------------- certificates */

	public byte[] encodeCert(int certType, byte[] certifiedKey, Ed25519TestSigner signer, long expirationHours) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(1);
		out.write(certType);
		out.write((int) (expirationHours >> 24) & 0xFF);
		out.write((int) (expirationHours >> 16) & 0xFF);
		out.write((int) (expirationHours >> 8) & 0xFF);
		out.write((int) expirationHours & 0xFF);
		out.write(Ed25519Certificate.KEY_TYPE_ED25519);
		out.write(certifiedKey, 0, 32);
		out.write(1); // N_EXTENSIONS
		out.write(0); out.write(32); // ExtLength
		out.write(Ed25519Certificate.EXT_TYPE_SIGNED_WITH_ED25519_KEY);
		out.write(0); // flags
		out.write(signer.publicKey, 0, 32);
		final byte[] body = out.toByteArray();
		final byte[] sig = signer.sign(body);
		out.write(sig, 0, sig.length);
		return out.toByteArray();
	}

	String certObject(byte[] cert) {
		return pem("ED25519 CERT", cert);
	}

	static String pem(String type, byte[] data) {
		final StringBuilder sb = new StringBuilder();
		sb.append("-----BEGIN ").append(type).append("-----\n");
		final String b64 = new String(Base64.encode(data), ASCII);
		for(int i = 0; i < b64.length(); i += 64) {
			sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
		}
		sb.append("-----END ").append(type).append("-----");
		return sb.toString();
	}

	static String b64NoPad(byte[] data) {
		String s = new String(Base64.encode(data), ASCII);
		while(s.endsWith("=")) {
			s = s.substring(0, s.length() - 1);
		}
		return s;
	}

	/* -------------------------------------------------------------- layers */

	public String encodeInnerLayer() {
		final long expiration = nowSeconds / 3600 + 54;
		final StringBuilder sb = new StringBuilder();
		sb.append("create2-formats 2\n");
		sb.append("flow-control 1-2 31\n");
		for(IntroPoint ip: introPoints) {
			final List<LinkSpecifier> specs = new ArrayList<LinkSpecifier>();
			specs.add(new LinkSpecifier(LinkSpecifier.TYPE_IPV4, ByteBuffer.allocate(6).put(ip.ipv4).putShort((short) ip.port).array()));
			specs.add(new LinkSpecifier(LinkSpecifier.TYPE_LEGACY_ID, ip.legacyId));
			specs.add(new LinkSpecifier(LinkSpecifier.TYPE_ED25519_ID, ip.ed25519Id));
			sb.append("introduction-point ").append(b64NoPad(LinkSpecifier.encodeList(specs))).append('\n');
			sb.append("onion-key ntor ").append(b64NoPad(ip.onionKey)).append('\n');
			sb.append("auth-key\n").append(certObject(encodeCert(Ed25519Certificate.CERT_TYPE_HS_IP_V_SIGNING, ip.authKey.publicKey, descriptorSigning, expiration))).append('\n');
			sb.append("enc-key ntor ").append(b64NoPad(ip.encKeyPublic)).append('\n');
			final byte[] encKeyEd = Ed25519.fromCurve25519PublicKey(ip.encKeyPublic, false);
			sb.append("enc-key-cert\n").append(certObject(encodeCert(Ed25519Certificate.CERT_TYPE_HS_IP_CC_SIGNING, encKeyEd, descriptorSigning, expiration))).append('\n');
		}
		return sb.toString();
	}

	public String encodeFirstLayer(byte[] innerCiphertext) {
		final StringBuilder sb = new StringBuilder();
		sb.append("desc-auth-type x25519\n");
		/* ephemeral x25519 key */
		final byte[] ephemeralPrivate = new byte[32];
		rng.nextBytes(ephemeralPrivate);
		ephemeralPrivate[0] &= 248;
		ephemeralPrivate[31] &= 127;
		ephemeralPrivate[31] |= 64;
		final byte[] ephemeralPublic = new byte[32];
		Curve25519.crypto_scalarmult_base(ephemeralPublic, ephemeralPrivate);
		sb.append("desc-auth-ephemeral-key ").append(b64NoPad(ephemeralPublic)).append('\n');
		final List<String> authLines = new ArrayList<String>();
		if(clientAuthPublicKey != null) {
			/*
			 * SECRET_SEED = x25519(KS_hs_desc_ephem, KP_hsc_desc_enc)
			 * KEYS = KDF(N_hs_subcred | SECRET_SEED, 40); CLIENT-ID = KEYS[0:8], COOKIE-KEY = KEYS[8:40]
			 */
			final byte[] secretSeed = new byte[32];
			Curve25519.crypto_scalarmult(secretSeed, ephemeralPrivate, clientAuthPublicKey);
			final byte[] keys = Keccak.shake256(40, subcredential, secretSeed);
			final byte[] clientId = Arrays.copyOfRange(keys, 0, 8);
			final byte[] cookieKey = Arrays.copyOfRange(keys, 8, 40);
			final byte[] iv = new byte[16];
			rng.nextBytes(iv);
			final byte[] encryptedCookie = aesCtr(cookieKey, iv, descriptorCookie);
			authLines.add("auth-client "+ b64NoPad(clientId) + " "+ b64NoPad(iv) + " "+ b64NoPad(encryptedCookie));
		}
		while(authLines.size() % 16 != 0) {
			final byte[] id = new byte[8], iv = new byte[16], cookie = new byte[16];
			rng.nextBytes(id); rng.nextBytes(iv); rng.nextBytes(cookie);
			authLines.add("auth-client "+ b64NoPad(id) + " "+ b64NoPad(iv) + " "+ b64NoPad(cookie));
		}
		java.util.Collections.shuffle(authLines, rng);
		for(String line: authLines) {
			sb.append(line).append('\n');
		}
		sb.append("encrypted\n").append(pem("MESSAGE", innerCiphertext));
		/* C tor omits the trailing newline here; pad with NUL to a multiple of 10000 */
		final byte[] plain = sb.toString().getBytes(ASCII);
		final int padded = ((plain.length + 9999) / 10000) * 10000;
		return new String(Arrays.copyOf(plain, padded), ASCII);
	}

	/**
	 * Encrypt one layer as the service does (independent implementation of
	 * rend-spec-v3 2.5.3 using the JDK cipher).
	 */
	public byte[] encryptLayer(byte[] plaintext, byte[] secretData, String stringConstant) {
		final byte[] salt = new byte[16];
		rng.nextBytes(salt);
		final byte[] secretInput = HSNtorKeyAgreement.concat(secretData, subcredential, HSNtorKeyAgreement.int8(revisionCounter));
		final byte[] keys = Keccak.shake256(32 + 16 + 32, secretInput, salt, stringConstant.getBytes(ASCII));
		final byte[] key = Arrays.copyOfRange(keys, 0, 32);
		final byte[] iv = Arrays.copyOfRange(keys, 32, 48);
		final byte[] macKey = Arrays.copyOfRange(keys, 48, 80);
		final byte[] encrypted = aesCtr(key, iv, plaintext);
		final byte[] mac = Keccak.digestSha3_256(HSNtorKeyAgreement.int8(32), macKey, HSNtorKeyAgreement.int8(16), salt, encrypted);
		return HSNtorKeyAgreement.concat(salt, encrypted, mac);
	}

	public byte[] encodeDescriptor() {
		final byte[] innerPlain = encodeInnerLayer().getBytes(ASCII);
		final byte[] innerSecretData = (descriptorCookie == null) ? blinded.publicKey : HSNtorKeyAgreement.concat(blinded.publicKey, descriptorCookie);
		final byte[] innerCipher = encryptLayer(innerPlain, innerSecretData, "hsdir-encrypted-data");
		final byte[] firstPlain = encodeFirstLayer(innerCipher).getBytes(ASCII);
		final byte[] superCipher = encryptLayer(firstPlain, blinded.publicKey, "hsdir-superencrypted-data");

		final long expiration = nowSeconds / 3600 + 54;
		final StringBuilder sb = new StringBuilder();
		sb.append("hs-descriptor 3\n");
		sb.append("descriptor-lifetime 180\n");
		sb.append("descriptor-signing-key-cert\n").append(certObject(encodeCert(Ed25519Certificate.CERT_TYPE_HS_DESC_SIGNING, descriptorSigning.publicKey, blinded, expiration))).append('\n');
		sb.append("revision-counter ").append(revisionCounter).append('\n');
		sb.append("superencrypted\n").append(pem("MESSAGE", superCipher)).append('\n');
		final byte[] body = sb.toString().getBytes(ASCII);
		final byte[] sig = descriptorSigning.sign(body, "Tor onion service descriptor sig v3");
		sb.append("signature ").append(b64NoPad(sig)).append('\n');
		return sb.toString().getBytes(ASCII);
	}

	static byte[] aesCtr(byte[] key, byte[] iv, byte[] data) {
		try {
			final Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
			c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
			return c.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
