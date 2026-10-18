package com.subgraph.orchid.circuits.hs;

import java.io.ByteArrayOutputStream;
import java.util.List;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.logging.Logger;

/**
 * Builds and sends the INTRODUCE1 cell of the version 3 protocol
 * (rend-spec-v3 section 3.2 [INTRO-PROTOCOL]) and processes INTRODUCE_ACK.
 *
 * <pre>
 *   INTRODUCE1 body:
 *     LEGACY_KEY_ID   [20 bytes]  all zero
 *     AUTH_KEY_TYPE   [1 byte]    0x02 (ed25519)
 *     AUTH_KEY_LEN    [2 bytes]   32
 *     AUTH_KEY        [32 bytes]  introduction point authentication key
 *     N_EXTENSIONS    [1 byte]    0
 *     ENCRYPTED:
 *       CLIENT_PK       [32 bytes]  X
 *       ENCRYPTED_DATA  [variable]  AES-256-CTR(ENC_KEY) of the plaintext below
 *       MAC             [32 bytes]  MAC(MAC_KEY, everything from LEGACY_KEY_ID through ENCRYPTED_DATA)
 *
 *   plaintext:
 *     RENDEZVOUS_COOKIE [20 bytes]
 *     N_EXTENSIONS      [1 byte]    0
 *     ONION_KEY_TYPE    [1 byte]    0x01 (ntor)
 *     ONION_KEY_LEN     [2 bytes]   32
 *     ONION_KEY         [32 bytes]  rendezvous point's ntor onion key
 *     NSPEC             [1 byte]
 *     link specifiers for the rendezvous point
 *     PAD               [variable]  zero bytes
 * </pre>
 */
public class HSV3IntroductionProcessor {
	private static final Logger logger = Logger.getInstance(HSV3IntroductionProcessor.class);

	static final int LEGACY_KEY_ID_LEN = 20;
	static final int AUTH_KEY_TYPE_ED25519 = 2;
	static final int ONION_KEY_TYPE_NTOR = 1;
	/** C Tor pads the (unencrypted) INTRODUCE1 header plus plaintext to at least this many bytes. */
	static final int INTRODUCE1_MIN_SIZE = 246;

	static final int ACK_STATUS_SUCCESS = 0;
	static final int ACK_STATUS_NOT_RECOGNIZED = 1;
	static final int ACK_STATUS_BAD_MESSAGE_FORMAT = 2;
	static final int ACK_STATUS_CANT_RELAY = 3;

	private final HiddenService hiddenService;
	private final Circuit introductionCircuit;
	private final HSV3IntroductionPoint introductionPoint;

	HSV3IntroductionProcessor(HiddenService hiddenService, Circuit introductionCircuit, HSV3IntroductionPoint introductionPoint) {
		this.hiddenService = hiddenService;
		this.introductionCircuit = introductionCircuit;
		this.introductionPoint = introductionPoint;
	}

	HSV3IntroductionPoint getIntroductionPoint() {
		return introductionPoint;
	}

	/**
	 * Send INTRODUCE1 and wait for INTRODUCE_ACK.
	 *
	 * @param kex The hs-ntor state created for this introduction point.
	 * @param rendezvousCookie The 20 byte cookie given to the rendezvous point.
	 * @param rendezvousRouter The rendezvous point.
	 * @return true if the introduction point acknowledged relaying the request.
	 */
	boolean sendIntroduce(HSNtorKeyAgreement kex, byte[] rendezvousCookie, Router rendezvousRouter) {
		final byte[] body = buildIntroduce1Body(kex, rendezvousCookie, rendezvousRouter);
		final RelayCell introduceCell = introductionCircuit.createRelayCell(RelayCell.RELAY_COMMAND_INTRODUCE1, 0, introductionCircuit.getFinalCircuitNode());
		if(body.length > introduceCell.cellBytesRemaining()) {
			logger.warn("INTRODUCE1 body too large for a relay cell: "+ body.length);
			return false;
		}
		introduceCell.putByteArray(body);
		introductionCircuit.sendRelayCell(introduceCell);

		final RelayCell response = introductionCircuit.receiveRelayCell();
		if(response == null) {
			logger.debug("Timeout waiting for response to INTRODUCE1 cell");
			return false;
		} else if(response.getRelayCommand() != RelayCell.RELAY_COMMAND_INTRODUCE_ACK) {
			logger.info("Unexpected relay cell type received waiting for response to INTRODUCE1 cell: "+ response.getRelayCommand());
			return false;
		}
		if(response.cellBytesRemaining() < 2) {
			logger.info("Malformed INTRODUCE_ACK cell");
			return false;
		}
		final int status = response.getShort();
		if(status == ACK_STATUS_SUCCESS) {
			return true;
		}
		logger.info("INTRODUCE_ACK indicates that introduction to "+ hiddenService.getOnionAddressForLogging() + " was not forwarded, status = "+ describeStatus(status));
		return false;
	}

	static String describeStatus(int status) {
		switch(status) {
		case ACK_STATUS_NOT_RECOGNIZED: return "NOT_RECOGNIZED";
		case ACK_STATUS_BAD_MESSAGE_FORMAT: return "BAD_MESSAGE_FORMAT";
		case ACK_STATUS_CANT_RELAY: return "CANT_RELAY";
		default: return Integer.toString(status);
		}
	}

	void markCircuitForClose() {
		introductionCircuit.markForClose();
	}

	byte[] buildIntroduce1Body(HSNtorKeyAgreement kex, byte[] rendezvousCookie, Router rendezvousRouter) {
		return buildIntroduce1Body(kex, rendezvousCookie, rendezvousRouter.getNTorOnionKey(), LinkSpecifier.forRouter(rendezvousRouter));
	}

	/**
	 * Build the complete INTRODUCE1 relay cell body.  Package private for tests.
	 */
	byte[] buildIntroduce1Body(HSNtorKeyAgreement kex, byte[] rendezvousCookie, byte[] rendezvousOnionKey, List<LinkSpecifier> rendezvousLinkSpecifiers) {
		final byte[] header = buildHeader();
		byte[] plaintext = buildPlaintext(rendezvousCookie, rendezvousOnionKey, rendezvousLinkSpecifiers);
		if(header.length + plaintext.length < INTRODUCE1_MIN_SIZE) {
			final byte[] padded = new byte[INTRODUCE1_MIN_SIZE - header.length];
			System.arraycopy(plaintext, 0, padded, 0, plaintext.length);
			plaintext = padded;
		}
		final byte[] encryptedData = kex.encryptIntroducePlaintext(plaintext);
		final byte[] macInput = HSNtorKeyAgreement.concat(header, kex.getClientPublicKey(), encryptedData);
		final byte[] mac = kex.computeIntroduceMac(macInput);
		return HSNtorKeyAgreement.concat(macInput, mac);
	}

	private byte[] buildHeader() {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(new byte[LEGACY_KEY_ID_LEN], 0, LEGACY_KEY_ID_LEN);
		out.write(AUTH_KEY_TYPE_ED25519);
		final byte[] authKey = introductionPoint.getAuthKey();
		out.write((authKey.length >> 8) & 0xFF);
		out.write(authKey.length & 0xFF);
		out.write(authKey, 0, authKey.length);
		out.write(0); // N_EXTENSIONS
		return out.toByteArray();
	}

	static byte[] buildPlaintext(byte[] rendezvousCookie, byte[] rendezvousOnionKey, List<LinkSpecifier> rendezvousLinkSpecifiers) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(rendezvousCookie, 0, rendezvousCookie.length);
		out.write(0); // N_EXTENSIONS
		out.write(ONION_KEY_TYPE_NTOR);
		out.write((rendezvousOnionKey.length >> 8) & 0xFF);
		out.write(rendezvousOnionKey.length & 0xFF);
		out.write(rendezvousOnionKey, 0, rendezvousOnionKey.length);
		final byte[] lspecs = LinkSpecifier.encodeList(rendezvousLinkSpecifiers);
		out.write(lspecs, 0, lspecs.length);
		return out.toByteArray();
	}
}
