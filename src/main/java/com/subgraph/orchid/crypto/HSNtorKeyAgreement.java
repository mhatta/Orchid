package com.subgraph.orchid.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;

import com.subgraph.orchid.misc.Utils;

/**
 * Client side of the "hs-ntor" handshake used by version 3 onion services,
 * specified in rend-spec-v3 section 2.5.1.1 [NTOR-WITH-EXTRA-DATA].
 *
 * The handshake has two halves:
 * <ol>
 *   <li>The client derives ENC_KEY / MAC_KEY from its ephemeral key and the
 *       introduction point encryption key B, and uses them to encrypt and
 *       authenticate the INTRODUCE1 payload ({@link #getIntroduceEncKey()},
 *       {@link #getIntroduceMacKey()}).</li>
 *   <li>When the service answers through the rendezvous point with
 *       RENDEZVOUS2 (Y | AUTH), the client verifies AUTH and expands
 *       NTOR_KEY_SEED into the circuit hop keys
 *       ({@link #completeHandshake(byte[], byte[])}).</li>
 * </ol>
 *
 * Notation follows the specification:
 * <pre>
 *   PROTOID     = "tor-hs-ntor-curve25519-sha3-256-1"
 *   t_hsenc     = PROTOID | ":hs_key_extract"
 *   t_hsverify  = PROTOID | ":hs_verify"
 *   t_hsmac     = PROTOID | ":hs_mac"
 *   m_hsexpand  = PROTOID | ":hs_key_expand"
 *   H           = SHA3-256
 *   MAC(key, m) = H(INT_8(len(key)) | key | m)
 *   KDF         = SHAKE-256
 * </pre>
 */
public class HSNtorKeyAgreement {
	private static final Charset ASCII = Charset.forName("ISO-8859-1");

	public static final String PROTOID = "tor-hs-ntor-curve25519-sha3-256-1";
	static final byte[] PROTOID_BYTES = PROTOID.getBytes(ASCII);
	static final byte[] T_HSENC = (PROTOID + ":hs_key_extract").getBytes(ASCII);
	static final byte[] T_HSVERIFY = (PROTOID + ":hs_verify").getBytes(ASCII);
	static final byte[] T_HSMAC = (PROTOID + ":hs_mac").getBytes(ASCII);
	static final byte[] M_HSEXPAND = (PROTOID + ":hs_key_expand").getBytes(ASCII);
	static final byte[] SERVER_STR = "Server".getBytes(ASCII);

	public static final int CURVE25519_KEY_LEN = 32;
	public static final int ED25519_KEY_LEN = 32;
	public static final int DIGEST256_LEN = 32;
	/** S_KEY_LEN: AES-256 */
	public static final int S_KEY_LEN = 32;
	/** MAC_KEY_LEN */
	public static final int MAC_KEY_LEN = 32;
	/** Length of the expanded circuit key material: Df | Db | Kf | Kb */
	public static final int KEY_EXPANSION_LEN = DIGEST256_LEN * 2 + S_KEY_LEN * 2;

	private final byte[] introAuthKey;   /* AUTH_KEY: introduction point authentication key (ed25519) */
	private final byte[] introEncKey;    /* B: introduction point encryption key (curve25519) */
	private final byte[] subcredential;  /* N_hs_subcred */
	private final byte[] secretKey_x;
	private final byte[] publicKey_X;
	private final byte[] introduceEncKey;
	private final byte[] introduceMacKey;

	/**
	 * Create a new handshake state.
	 *
	 * @param introAuthKey The introduction point's ed25519 authentication key (from the descriptor "auth-key" cert).
	 * @param introEncKey The introduction point's curve25519 encryption key (from the descriptor "enc-key" line).
	 * @param subcredential The N_hs_subcred value for the current time period.
	 */
	public HSNtorKeyAgreement(byte[] introAuthKey, byte[] introEncKey, byte[] subcredential) {
		this(introAuthKey, introEncKey, subcredential, generateSecretKey());
	}

	/** Constructor with an explicit ephemeral secret key; used by tests. */
	public HSNtorKeyAgreement(byte[] introAuthKey, byte[] introEncKey, byte[] subcredential, byte[] secretKey_x) {
		checkLength(introAuthKey, ED25519_KEY_LEN, "AUTH_KEY");
		checkLength(introEncKey, CURVE25519_KEY_LEN, "B");
		checkLength(subcredential, DIGEST256_LEN, "subcredential");
		this.introAuthKey = introAuthKey.clone();
		this.introEncKey = introEncKey.clone();
		this.subcredential = subcredential.clone();
		this.secretKey_x = secretKey_x.clone();
		this.publicKey_X = new byte[CURVE25519_KEY_LEN];
		Curve25519.crypto_scalarmult_base(publicKey_X, this.secretKey_x);

		/*
		 * intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
		 * info = m_hsexpand | subcredential
		 * hs_keys = KDF(intro_secret_hs_input | t_hsenc | info, S_KEY_LEN+MAC_KEY_LEN)
		 */
		final byte[] expBx = scalarMult(this.secretKey_x, this.introEncKey);
		final byte[] introSecretInput = concat(expBx, this.introAuthKey, publicKey_X, this.introEncKey, PROTOID_BYTES);
		final byte[] info = concat(M_HSEXPAND, this.subcredential);
		final byte[] hsKeys = Keccak.shake256(S_KEY_LEN + MAC_KEY_LEN, introSecretInput, T_HSENC, info);
		this.introduceEncKey = Arrays.copyOfRange(hsKeys, 0, S_KEY_LEN);
		this.introduceMacKey = Arrays.copyOfRange(hsKeys, S_KEY_LEN, S_KEY_LEN + MAC_KEY_LEN);
	}

	private static void checkLength(byte[] b, int len, String name) {
		if(b == null || b.length != len) {
			throw new IllegalArgumentException(name + " must be "+ len +" bytes");
		}
	}

	static byte[] generateSecretKey() {
		final byte[] key = new TorRandom().getBytes(32);
		key[0] &= 248;
		key[31] &= 127;
		key[31] |= 64;
		return key;
	}

	/** X: the client's single-use curve25519 public key, sent as CLIENT_PK in INTRODUCE1. */
	public byte[] getClientPublicKey() {
		return publicKey_X.clone();
	}

	/** ENC_KEY: the AES-256 key used to encrypt the INTRODUCE1 ENCRYPTED_DATA (with an all-zero IV). */
	public byte[] getIntroduceEncKey() {
		return introduceEncKey.clone();
	}

	/** MAC_KEY: the key used to authenticate the INTRODUCE1 cell. */
	public byte[] getIntroduceMacKey() {
		return introduceMacKey.clone();
	}

	/**
	 * Encrypt the INTRODUCE1 plaintext with ENC_KEY (AES-256-CTR, zero IV).
	 */
	public byte[] encryptIntroducePlaintext(byte[] plaintext) {
		final byte[] out = plaintext.clone();
		TorStreamCipher.createFromKeyBytes(introduceEncKey).encrypt(out);
		return out;
	}

	/**
	 * Compute the INTRODUCE1 MAC over the cell contents from the beginning of
	 * the cell (LEGACY_KEY_ID) through the end of ENCRYPTED_DATA.
	 */
	public byte[] computeIntroduceMac(byte[] macInput) {
		return mac(introduceMacKey, macInput);
	}

	/**
	 * Complete the handshake from the RENDEZVOUS2 payload (SERVER_PK Y | AUTH).
	 *
	 * @param serverPublicKey_Y The service's ephemeral curve25519 public key.
	 * @param authCandidate The AUTH_INPUT_MAC value received from the service.
	 * @return The expanded key material Df | Db | Kf | Kb ({@link #KEY_EXPANSION_LEN} bytes),
	 *         or null if the AUTH value did not verify.
	 */
	public byte[] completeHandshake(byte[] serverPublicKey_Y, byte[] authCandidate) {
		checkLength(serverPublicKey_Y, CURVE25519_KEY_LEN, "Y");
		checkLength(authCandidate, DIGEST256_LEN, "AUTH");
		/*
		 * rend_secret_hs_input = EXP(Y,x) | EXP(B,x) | AUTH_KEY | B | X | Y | PROTOID
		 * NTOR_KEY_SEED = MAC(rend_secret_hs_input, t_hsenc)
		 * verify = MAC(rend_secret_hs_input, t_hsverify)
		 * auth_input = verify | AUTH_KEY | B | Y | X | PROTOID | "Server"
		 * AUTH_INPUT_MAC = MAC(auth_input, t_hsmac)
		 */
		final byte[] expYx = scalarMult(secretKey_x, serverPublicKey_Y);
		final byte[] expBx = scalarMult(secretKey_x, introEncKey);
		boolean bad = isAllZero(expYx) | isAllZero(expBx);
		final byte[] rendSecretInput = concat(expYx, expBx, introAuthKey, introEncKey, publicKey_X, serverPublicKey_Y, PROTOID_BYTES);
		final byte[] ntorKeySeed = mac(rendSecretInput, T_HSENC);
		final byte[] verify = mac(rendSecretInput, T_HSVERIFY);
		final byte[] authInput = concat(verify, introAuthKey, introEncKey, serverPublicKey_Y, publicKey_X, PROTOID_BYTES, SERVER_STR);
		final byte[] authInputMac = mac(authInput, T_HSMAC);
		bad |= !Utils.constantTimeArrayEquals(authInputMac, authCandidate);
		if(bad) {
			return null;
		}
		return expandKeys(ntorKeySeed);
	}

	/**
	 * K = KDF(NTOR_KEY_SEED | m_hsexpand, SHA3_256_LEN * 2 + S_KEY_LEN * 2)
	 */
	public static byte[] expandKeys(byte[] ntorKeySeed) {
		return Keccak.shake256(KEY_EXPANSION_LEN, ntorKeySeed, M_HSEXPAND);
	}

	/** MAC(key, message) = H(INT_8(len(key)) | key | message) with H = SHA3-256. */
	public static byte[] mac(byte[] key, byte[] message) {
		return Keccak.digestSha3_256(int8(key.length), key, message);
	}

	/** INT_8(n): 8 byte big-endian encoding. */
	public static byte[] int8(long value) {
		final byte[] b = new byte[8];
		for(int i = 7; i >= 0; i--) {
			b[i] = (byte) (value & 0xFF);
			value >>>= 8;
		}
		return b;
	}

	static byte[] scalarMult(byte[] secret, byte[] peerPublic) {
		final byte[] out = new byte[CURVE25519_KEY_LEN];
		Curve25519.crypto_scalarmult(out, secret, peerPublic);
		return out;
	}

	static boolean isAllZero(byte[] bs) {
		int acc = 0;
		for(byte b: bs) {
			acc |= b;
		}
		return acc == 0;
	}

	public static byte[] concat(byte[]... parts) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		for(byte[] p: parts) {
			out.write(p, 0, p.length);
		}
		return out.toByteArray();
	}
}
