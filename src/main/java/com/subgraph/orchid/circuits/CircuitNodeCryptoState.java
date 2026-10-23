package com.subgraph.orchid.circuits;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorStreamCipher;
import com.subgraph.orchid.data.HexDigest;

public class CircuitNodeCryptoState {
	/** Key material layout for ordinary (TAP/ntor) hops: Df | Db | Kf | Kb with SHA-1 digests and AES-128 keys. */
	public final static int KEY_MATERIAL_SIZE = TorMessageDigest.TOR_DIGEST_SIZE * 2 + TorStreamCipher.KEY_LEN * 2;

	/** Key length used for a v3 onion service rendezvous hop (AES-256). */
	public final static int HS_V3_KEY_LEN = 32;
	/** Key material layout for a v3 onion service rendezvous hop: Df | Db | Kf | Kb with SHA3-256 digests and AES-256 keys. */
	public final static int HS_V3_KEY_MATERIAL_SIZE = TorMessageDigest.TOR_DIGEST256_SIZE * 2 + HS_V3_KEY_LEN * 2;

	public static CircuitNodeCryptoState createFromKeyMaterial(byte[] keyMaterial, byte[] verifyDigest) {
		return new CircuitNodeCryptoState(keyMaterial, verifyDigest, TorMessageDigest.Algorithm.SHA1, TorStreamCipher.KEY_LEN);
	}

	/**
	 * Create the crypto state for the virtual hop to a v3 onion service, as
	 * derived from the hs-ntor handshake (rend-spec-v3 section 2.5 / [NTOR-WITH-EXTRA-DATA]):
	 * the digests are SHA3-256 and the ciphers are AES-256-CTR.
	 */
	public static CircuitNodeCryptoState createFromHSV3KeyMaterial(byte[] keyMaterial) {
		return new CircuitNodeCryptoState(keyMaterial, null, TorMessageDigest.Algorithm.SHA3_256, HS_V3_KEY_LEN);
	}

	private final HexDigest checksumDigest;
	private final TorMessageDigest forwardDigest;
	private final TorMessageDigest backwardDigest;
	private final TorStreamCipher forwardCipher;
	private final TorStreamCipher backwardCipher;

	static private byte[] extractBytes(byte[] keyMaterial, int offset, int length) {
		final byte[] bytes = new byte[length];
		System.arraycopy(keyMaterial, offset, bytes, 0, length);
		return bytes;
	}

	private CircuitNodeCryptoState(byte[] keyMaterial, byte[] verifyDigest, TorMessageDigest.Algorithm digestAlgorithm, int cipherKeyLen) {
		checksumDigest = (verifyDigest == null) ? null : HexDigest.createFromDigestBytes(verifyDigest);
		final int digestLen = (digestAlgorithm == TorMessageDigest.Algorithm.SHA1) ? TorMessageDigest.TOR_DIGEST_SIZE : TorMessageDigest.TOR_DIGEST256_SIZE;
		if(keyMaterial.length < 2 * digestLen + 2 * cipherKeyLen) {
			throw new IllegalArgumentException("Key material too short: "+ keyMaterial.length);
		}
		int offset = 0;

		forwardDigest = new TorMessageDigest(digestAlgorithm);
		forwardDigest.update(extractBytes(keyMaterial, offset, digestLen));
		offset += digestLen;

		backwardDigest = new TorMessageDigest(digestAlgorithm);
		backwardDigest.update(extractBytes(keyMaterial, offset, digestLen));
		offset += digestLen;

		forwardCipher = TorStreamCipher.createFromKeyBytes(extractBytes(keyMaterial, offset, cipherKeyLen));
		offset += cipherKeyLen;

		backwardCipher = TorStreamCipher.createFromKeyBytes(extractBytes(keyMaterial, offset, cipherKeyLen));
	}

	boolean verifyPacketDigest(HexDigest packetDigest) {
		return checksumDigest != null && checksumDigest.equals(packetDigest);
	}

	void encryptForwardCell(Cell cell) {
		forwardCipher.encrypt(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
	}

	boolean decryptBackwardCell(Cell cell) {
		backwardCipher.encrypt(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
		return isRecognizedCell(cell);
	}

	void updateForwardDigest(Cell cell) {
		forwardDigest.update(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
	}

	byte[] getForwardDigestBytes() {
		return forwardDigest.getDigestBytes();
	}

	/** The running digest of the cells received from this hop. */
	byte[] getBackwardDigestBytes() {
		return backwardDigest.getDigestBytes();
	}

	private boolean isRecognizedCell(Cell cell) {
		if(cell.getShortAt(RelayCell.RECOGNIZED_OFFSET) != 0)
			return false;

		final byte[] digest = extractRelayDigest(cell);
		final byte[] peek = backwardDigest.peekDigest(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
		for(int i = 0; i < 4; i++)
			if(digest[i] != peek[i]) {
				replaceRelayDigest(cell, digest);
				return false;
			}
		backwardDigest.update(cell.getCellBytes(), Cell.CELL_HEADER_LEN, Cell.CELL_PAYLOAD_LEN);
		replaceRelayDigest(cell, digest);
		return true;
	}

	private byte[] extractRelayDigest(Cell cell) {
		final byte[] digest = new byte[4];
		for(int i = 0; i < 4; i++) {
			digest[i] = (byte) cell.getByteAt(i + RelayCell.DIGEST_OFFSET);
			cell.putByteAt(i + RelayCell.DIGEST_OFFSET, 0);
		}
		return digest;
	}

	private void replaceRelayDigest(Cell cell, byte[] digest) {
		for(int i = 0; i < 4; i++)
			cell.putByteAt(i + RelayCell.DIGEST_OFFSET, digest[i] & 0xFF);
	}
}
