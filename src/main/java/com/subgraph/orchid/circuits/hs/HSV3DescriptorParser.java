package com.subgraph.orchid.circuits.hs;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.Curve25519;
import com.subgraph.orchid.crypto.Ed25519;
import com.subgraph.orchid.crypto.Ed25519Certificate;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.crypto.Keccak;
import com.subgraph.orchid.crypto.TorStreamCipher;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.misc.Utils;

/**
 * Parser for version 3 onion service descriptors (rend-spec-v3 sections 2.4
 * and 2.5).  Parsing a descriptor involves:
 * <ol>
 *   <li>tokenizing the outer wrapper and verifying its signature with the
 *       descriptor signing key, which must itself be certified by the blinded
 *       key we computed for the service and time period,</li>
 *   <li>decrypting the "superencrypted" layer (keyed by the blinded key and
 *       subcredential), which yields the client authorization data and the
 *       "encrypted" inner layer,</li>
 *   <li>decrypting the inner layer (additionally keyed by the descriptor
 *       cookie when client authorization is in use) and reading the
 *       introduction points, each with its certified keys.</li>
 * </ol>
 */
public final class HSV3DescriptorParser {
	private static final Logger logger = Logger.getInstance(HSV3DescriptorParser.class);
	private static final Charset ASCII = Charset.forName("ISO-8859-1");

	static final String SIG_PREFIX = "Tor onion service descriptor sig v3";
	static final byte[] SUPERENCRYPTED_CONST = "hsdir-superencrypted-data".getBytes(ASCII);
	static final byte[] ENCRYPTED_CONST = "hsdir-encrypted-data".getBytes(ASCII);
	static final int SALT_LEN = 16;
	static final int S_KEY_LEN = 32;
	static final int S_IV_LEN = 16;
	static final int MAC_KEY_LEN = 32;
	static final int MAC_LEN = 32;
	static final int CLIENT_ID_LEN = 8;
	static final int COOKIE_KEY_LEN = 32;
	static final int DESCRIPTOR_COOKIE_LEN = 16;
	static final int MIN_LIFETIME_MINUTES = 30;
	static final int MAX_LIFETIME_MINUTES = 720;

	private final byte[] blindedPublicKey;
	private final byte[] subcredential;
	private final byte[] clientAuthPrivateKey;
	private final long nowSeconds;
	private final long timePeriodNumber;

	/**
	 * @param blindedPublicKey The blinded key the descriptor was fetched with.
	 * @param subcredential N_hs_subcred for the same time period.
	 * @param clientAuthPrivateKey The client's x25519 private key for restricted discovery, or null.
	 * @param nowSeconds Current time, used to check certificate expiration.
	 * @param timePeriodNumber The time period the descriptor belongs to (informational).
	 */
	public HSV3DescriptorParser(byte[] blindedPublicKey, byte[] subcredential, byte[] clientAuthPrivateKey, long nowSeconds, long timePeriodNumber) {
		this.blindedPublicKey = blindedPublicKey;
		this.subcredential = subcredential;
		this.clientAuthPrivateKey = clientAuthPrivateKey;
		this.nowSeconds = nowSeconds;
		this.timePeriodNumber = timePeriodNumber;
	}

	/**
	 * Parse, verify and decrypt a descriptor document.
	 *
	 * @throws TorParsingException if the document is malformed, fails
	 *         verification, or cannot be decrypted (e.g. missing client authorization).
	 */
	public HSV3Descriptor parse(byte[] document) {
		final List<Item> items = tokenize(document, 0, document.length);
		return parseOuterLayer(document, items);
	}

	/* ---------------------------------------------------------------- outer layer */

	private HSV3Descriptor parseOuterLayer(byte[] document, List<Item> items) {
		if(items.isEmpty() || !"hs-descriptor".equals(items.get(0).keyword)) {
			throw new TorParsingException("Descriptor does not start with hs-descriptor");
		}
		final int version = items.get(0).intArg(0);
		if(version != 3) {
			throw new TorParsingException("Unsupported hs-descriptor version "+ version);
		}
		final Item last = items.get(items.size() - 1);
		if(!"signature".equals(last.keyword)) {
			throw new TorParsingException("Descriptor does not end with a signature line");
		}

		final long lifetime = exactlyOnce(items, "descriptor-lifetime").longArg(0);
		if(lifetime < MIN_LIFETIME_MINUTES || lifetime > MAX_LIFETIME_MINUTES) {
			throw new TorParsingException("Invalid descriptor-lifetime "+ lifetime);
		}
		final Item certItem = exactlyOnce(items, "descriptor-signing-key-cert");
		final Ed25519Certificate signingKeyCert = parseCert(certItem, "descriptor-signing-key-cert");
		/*
		 * The cert must be of type 08 and the blinded key must appear in the
		 * signing-key extension; verifying the signature under the blinded key
		 * is what ties the descriptor to the onion address.
		 */
		if(!signingKeyCert.isValid(Ed25519Certificate.CERT_TYPE_HS_DESC_SIGNING, blindedPublicKey, nowSeconds)) {
			throw new TorParsingException("Descriptor signing key certificate is invalid or not signed by the expected blinded key");
		}
		final long revisionCounter = exactlyOnce(items, "revision-counter").longArg(0);
		final Item superencrypted = exactlyOnce(items, "superencrypted");
		final byte[] superencryptedBlob = superencrypted.objectBytes("MESSAGE");

		/* Signature: over the document up to and including the newline before "signature " */
		final int sigStart = indexOf(document, "\nsignature ".getBytes(ASCII));
		if(sigStart < 0) {
			throw new TorParsingException("Malformed signature line");
		}
		final byte[] signature = decodeBase64(last.arg(0));
		if(signature.length != 64) {
			throw new TorParsingException("Invalid descriptor signature length "+ signature.length);
		}
		final byte[] descriptorSigningKey = signingKeyCert.getCertifiedKey();
		if(!Ed25519.verifyPrefixed(descriptorSigningKey, SIG_PREFIX, document, 0, sigStart + 1, signature)) {
			throw new TorParsingException("Invalid signature on service descriptor");
		}

		/* First (superencrypted) layer */
		final byte[] firstLayer = decryptLayer(superencryptedBlob, blindedPublicKey, revisionCounter, SUPERENCRYPTED_CONST);
		final byte[] descriptorCookie = parseFirstLayerAndGetCookie(firstLayer);
		final Item encrypted = exactlyOnce(tokenize(firstLayer, 0, unpaddedLength(firstLayer)), "encrypted");
		final byte[] encryptedBlob = encrypted.objectBytes("MESSAGE");

		/* Second (encrypted) layer */
		final byte[] secretData = (descriptorCookie == null) ? blindedPublicKey : HSNtorKeyAgreement.concat(blindedPublicKey, descriptorCookie);
		final byte[] innerLayer = decryptLayer(encryptedBlob, secretData, revisionCounter, ENCRYPTED_CONST);
		return parseInnerLayer(innerLayer, lifetime, signingKeyCert, revisionCounter, descriptorSigningKey);
	}

	/* ---------------------------------------------------------------- first layer */

	/**
	 * Parse the superencrypted layer plaintext and, if client authorization is
	 * configured, recover the descriptor cookie.  Returns null when no cookie
	 * applies (the service does not use restricted discovery or we have no key
	 * for it; in the latter case the inner layer will fail to decrypt).
	 */
	byte[] parseFirstLayerAndGetCookie(byte[] firstLayer) {
		final List<Item> items = tokenize(firstLayer, 0, unpaddedLength(firstLayer));
		if(items.isEmpty() || !"desc-auth-type".equals(items.get(0).keyword)) {
			throw new TorParsingException("Superencrypted layer does not start with desc-auth-type");
		}
		final String authType = items.get(0).arg(0);
		if(!"x25519".equals(authType)) {
			throw new TorParsingException("Unsupported desc-auth-type "+ authType);
		}
		final byte[] ephemeralKey = decodeBase64(exactlyOnce(items, "desc-auth-ephemeral-key").arg(0));
		if(ephemeralKey.length != 32) {
			throw new TorParsingException("Invalid desc-auth-ephemeral-key length");
		}
		if(clientAuthPrivateKey == null) {
			return null;
		}
		/*
		 * SECRET_SEED = x25519(KS_hsc_desc_enc, KP_hss_desc_enc)
		 * KEYS = KDF(N_hs_subcred | SECRET_SEED, 40)
		 * CLIENT-ID = KEYS[0:8], COOKIE-KEY = KEYS[8:40]
		 */
		final byte[] secretSeed = new byte[32];
		Curve25519.crypto_scalarmult(secretSeed, clientAuthPrivateKey, ephemeralKey);
		final byte[] keys = Keccak.shake256(CLIENT_ID_LEN + COOKIE_KEY_LEN, subcredential, secretSeed);
		final byte[] clientId = Arrays.copyOfRange(keys, 0, CLIENT_ID_LEN);
		final byte[] cookieKey = Arrays.copyOfRange(keys, CLIENT_ID_LEN, CLIENT_ID_LEN + COOKIE_KEY_LEN);
		for(Item item: items) {
			if(!"auth-client".equals(item.keyword) || item.args.size() < 3) {
				continue;
			}
			final byte[] id = decodeBase64(item.arg(0));
			if(!Arrays.equals(id, clientId)) {
				continue;
			}
			final byte[] iv = decodeBase64(item.arg(1));
			final byte[] encryptedCookie = decodeBase64(item.arg(2));
			if(iv.length != S_IV_LEN || encryptedCookie.length != DESCRIPTOR_COOKIE_LEN) {
				throw new TorParsingException("Malformed auth-client line");
			}
			final byte[] cookie = encryptedCookie.clone();
			TorStreamCipher.createFromKeyBytesWithIV(cookieKey, iv).encrypt(cookie);
			return cookie;
		}
		logger.info("Client authorization key configured but no matching auth-client entry found in descriptor");
		return null;
	}

	/* ---------------------------------------------------------------- inner layer */

	private HSV3Descriptor parseInnerLayer(byte[] innerLayer, long lifetime, Ed25519Certificate signingKeyCert, long revisionCounter, byte[] descriptorSigningKey) {
		final List<Item> items = tokenize(innerLayer, 0, unpaddedLength(innerLayer));
		if(items.isEmpty() || !"create2-formats".equals(items.get(0).keyword)) {
			throw new TorParsingException("Encrypted layer does not start with create2-formats");
		}
		final List<Integer> formats = new ArrayList<Integer>();
		for(String s: items.get(0).args) {
			try {
				formats.add(Integer.parseInt(s));
			} catch (NumberFormatException e) {
				throw new TorParsingException("Invalid create2-formats value "+ s);
			}
		}
		if(!formats.contains(2)) {
			throw new TorParsingException("Service does not support the ntor create2 format");
		}
		boolean introAuthRequired = false;
		boolean singleOnion = false;
		final List<HSV3IntroductionPoint> introPoints = new ArrayList<HSV3IntroductionPoint>();
		int i = 1;
		while(i < items.size() && !"introduction-point".equals(items.get(i).keyword)) {
			final Item item = items.get(i);
			if("intro-auth-required".equals(item.keyword)) {
				/* Only "ed25519" is defined and we do not implement it; any value makes the service unusable for us. */
				introAuthRequired = true;
			} else if("single-onion-service".equals(item.keyword)) {
				singleOnion = true;
			}
			/* flow-control, pow-params, proto and unknown lines are ignored */
			i++;
		}
		while(i < items.size()) {
			final int start = i;
			i++;
			while(i < items.size() && !"introduction-point".equals(items.get(i).keyword)) {
				i++;
			}
			final HSV3IntroductionPoint ip = parseIntroductionPoint(items.subList(start, i), descriptorSigningKey);
			if(ip != null) {
				introPoints.add(ip);
			}
		}
		if(introPoints.isEmpty()) {
			logger.info("Descriptor contains no usable introduction points");
		}
		return new HSV3Descriptor(lifetime, signingKeyCert, revisionCounter, singleOnion, introAuthRequired, formats, introPoints, nowSeconds, timePeriodNumber);
	}

	private HSV3IntroductionPoint parseIntroductionPoint(List<Item> items, byte[] descriptorSigningKey) {
		try {
			final List<LinkSpecifier> lspecs = LinkSpecifier.parseList(decodeBase64(items.get(0).arg(0)));
			byte[] onionKey = null;
			byte[] encKey = null;
			Ed25519Certificate authKeyCert = null;
			Ed25519Certificate encKeyCert = null;
			for(Item item: items.subList(1, items.size())) {
				if("onion-key".equals(item.keyword)) {
					if("ntor".equals(item.arg(0))) {
						onionKey = requireLength(decodeBase64(item.arg(1)), 32, "onion-key");
					}
				} else if("enc-key".equals(item.keyword)) {
					if("ntor".equals(item.arg(0))) {
						encKey = requireLength(decodeBase64(item.arg(1)), 32, "enc-key");
					}
				} else if("auth-key".equals(item.keyword)) {
					authKeyCert = parseCert(item, "auth-key");
				} else if("enc-key-cert".equals(item.keyword)) {
					encKeyCert = parseCert(item, "enc-key-cert");
				}
				/* legacy-key / legacy-key-cert and unknown items are ignored */
			}
			if(onionKey == null || encKey == null || authKeyCert == null || encKeyCert == null) {
				throw new TorParsingException("Introduction point is missing a required field");
			}
			/* auth-key: cert type 09, certifies the intro point auth key, signed with the descriptor signing key */
			if(!authKeyCert.isValid(Ed25519Certificate.CERT_TYPE_HS_IP_V_SIGNING, descriptorSigningKey, nowSeconds)) {
				throw new TorParsingException("Invalid introduction point auth-key certificate");
			}
			/* enc-key-cert: cert type 0B, cross-certifies the enc-key, signed with the descriptor signing key */
			if(!encKeyCert.isValid(Ed25519Certificate.CERT_TYPE_HS_IP_CC_SIGNING, descriptorSigningKey, nowSeconds)) {
				throw new TorParsingException("Invalid introduction point enc-key-cert certificate");
			}
			final byte[] expectedSubject = Ed25519.fromCurve25519PublicKey(encKey, false);
			if(!Arrays.equals(expectedSubject, encKeyCert.getCertifiedKey())) {
				logger.debug("Introduction point enc-key-cert subject does not match the converted enc-key");
			}
			return new HSV3IntroductionPoint(lspecs, onionKey, authKeyCert, encKey, encKeyCert);
		} catch (TorParsingException e) {
			logger.info("Ignoring unparseable introduction point: "+ e.getMessage());
			return null;
		}
	}

	/* ---------------------------------------------------------------- decryption */

	/**
	 * Decrypt one descriptor layer (rend-spec-v3 section 2.5.3):
	 * <pre>
	 *   secret_input = SECRET_DATA | N_hs_subcred | INT_8(revision_counter)
	 *   keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)
	 *   SECRET_KEY = keys[0:S_KEY_LEN], SECRET_IV = next S_IV_LEN, MAC_KEY = next MAC_KEY_LEN
	 *   blob = SALT | ENCRYPTED | MAC
	 *   MAC = H(INT_8(len(MAC_KEY)) | MAC_KEY | INT_8(len(SALT)) | SALT | ENCRYPTED)
	 *   plaintext = AES-256-CTR(SECRET_KEY, SECRET_IV) XOR ENCRYPTED
	 * </pre>
	 */
	byte[] decryptLayer(byte[] blob, byte[] secretData, long revisionCounter, byte[] stringConstant) {
		if(blob.length <= SALT_LEN + MAC_LEN) {
			throw new TorParsingException("Encrypted descriptor layer is too short");
		}
		final byte[] salt = Arrays.copyOfRange(blob, 0, SALT_LEN);
		final byte[] encrypted = Arrays.copyOfRange(blob, SALT_LEN, blob.length - MAC_LEN);
		final byte[] mac = Arrays.copyOfRange(blob, blob.length - MAC_LEN, blob.length);

		final byte[] secretInput = HSNtorKeyAgreement.concat(secretData, subcredential, HSNtorKeyAgreement.int8(revisionCounter));
		final byte[] keys = Keccak.shake256(S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN, secretInput, salt, stringConstant);
		final byte[] secretKey = Arrays.copyOfRange(keys, 0, S_KEY_LEN);
		final byte[] secretIv = Arrays.copyOfRange(keys, S_KEY_LEN, S_KEY_LEN + S_IV_LEN);
		final byte[] macKey = Arrays.copyOfRange(keys, S_KEY_LEN + S_IV_LEN, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN);

		final byte[] expectedMac = Keccak.digestSha3_256(HSNtorKeyAgreement.int8(macKey.length), macKey, HSNtorKeyAgreement.int8(salt.length), salt, encrypted);
		if(!Utils.constantTimeArrayEquals(expectedMac, mac)) {
			throw new TorParsingException("Descriptor layer MAC check failed (wrong client authorization key?)");
		}
		final byte[] plaintext = encrypted.clone();
		TorStreamCipher.createFromKeyBytesWithIV(secretKey, secretIv).encrypt(plaintext);
		return plaintext;
	}

	/* ---------------------------------------------------------------- tokenizer */

	/** A keyword line with its arguments and optional "-----BEGIN X-----" object. */
	static final class Item {
		final String keyword;
		final List<String> args;
		String objectType;
		final StringBuilder objectBody = new StringBuilder();

		Item(String keyword, List<String> args) {
			this.keyword = keyword;
			this.args = args;
		}

		String arg(int i) {
			if(i >= args.size()) {
				throw new TorParsingException("Missing argument "+ i + " for "+ keyword);
			}
			return args.get(i);
		}

		int intArg(int i) {
			try {
				return Integer.parseInt(arg(i));
			} catch (NumberFormatException e) {
				throw new TorParsingException("Invalid integer argument for "+ keyword);
			}
		}

		long longArg(int i) {
			try {
				return Long.parseLong(arg(i));
			} catch (NumberFormatException e) {
				throw new TorParsingException("Invalid integer argument for "+ keyword);
			}
		}

		byte[] objectBytes(String expectedType) {
			if(objectType == null) {
				throw new TorParsingException("Missing object for "+ keyword);
			}
			if(!expectedType.equals(objectType)) {
				throw new TorParsingException("Unexpected object type "+ objectType + " for "+ keyword);
			}
			return decodeBase64(objectBody.toString());
		}
	}

	static List<Item> tokenize(byte[] data, int offset, int length) {
		final String text = new String(data, offset, length, ASCII);
		final String[] lines = text.split("\n", -1);
		final List<Item> items = new ArrayList<Item>();
		Item current = null;
		boolean inObject = false;
		for(String rawLine: lines) {
			final String line = rawLine.endsWith("\r") ? rawLine.substring(0, rawLine.length() - 1) : rawLine;
			if(inObject) {
				if(line.startsWith("-----END ")) {
					inObject = false;
				} else {
					current.objectBody.append(line.trim());
				}
				continue;
			}
			if(line.isEmpty()) {
				continue;
			}
			if(line.startsWith("-----BEGIN ") && line.endsWith("-----")) {
				if(current == null || current.objectType != null) {
					throw new TorParsingException("Unexpected object in descriptor");
				}
				current.objectType = line.substring("-----BEGIN ".length(), line.length() - 5);
				inObject = true;
				continue;
			}
			final String[] parts = line.trim().split("[ \t]+");
			final List<String> args = new ArrayList<String>(Arrays.asList(parts).subList(1, parts.length));
			current = new Item(parts[0], args);
			items.add(current);
		}
		if(inObject) {
			throw new TorParsingException("Unterminated object in descriptor");
		}
		return items;
	}

	static Item exactlyOnce(List<Item> items, String keyword) {
		Item found = null;
		for(Item item: items) {
			if(keyword.equals(item.keyword)) {
				if(found != null) {
					throw new TorParsingException("Duplicate "+ keyword + " line");
				}
				found = item;
			}
		}
		if(found == null) {
			throw new TorParsingException("Missing "+ keyword + " line");
		}
		return found;
	}

	static Ed25519Certificate parseCert(Item item, String what) {
		try {
			return Ed25519Certificate.parse(item.objectBytes("ED25519 CERT"));
		} catch (TorParsingException e) {
			throw new TorParsingException("Invalid "+ what + ": "+ e.getMessage());
		}
	}

	private static byte[] requireLength(byte[] b, int len, String what) {
		if(b.length != len) {
			throw new TorParsingException("Invalid "+ what + " length "+ b.length);
		}
		return b;
	}

	/** Length of the plaintext excluding trailing NUL padding. */
	static int unpaddedLength(byte[] plaintext) {
		int len = plaintext.length;
		while(len > 0 && plaintext[len - 1] == 0) {
			len--;
		}
		return len;
	}

	static int indexOf(byte[] haystack, byte[] needle) {
		outer:
		for(int i = 0; i + needle.length <= haystack.length; i++) {
			for(int j = 0; j < needle.length; j++) {
				if(haystack[i + j] != needle[j]) {
					continue outer;
				}
			}
			return i;
		}
		return -1;
	}

	/** Decode base64 with or without trailing '=' padding. */
	static byte[] decodeBase64(String s) {
		final StringBuilder sb = new StringBuilder(s.trim());
		while((sb.length() % 4) != 0) {
			sb.append('=');
		}
		try {
			return Base64.decode(sb.toString());
		} catch (RuntimeException e) {
			throw new TorParsingException("Invalid base64 data in descriptor");
		}
	}
}
