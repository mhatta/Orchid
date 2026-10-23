package com.subgraph.orchid.circuits;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.misc.Utils;

public class CircuitNodeImpl implements CircuitNode {
	
	public static CircuitNode createAnonymous(CircuitNode previous, byte[] keyMaterial, byte[] verifyDigest) {
		return createNode(null, previous, keyMaterial, verifyDigest);
	}

	/**
	 * Create the anonymous (router-less) virtual hop representing a v3 onion
	 * service at the far end of a rendezvous circuit.  The key material is the
	 * output of the hs-ntor key expansion (Df | Db | Kf | Kb, SHA3-256/AES-256).
	 */
	public static CircuitNode createAnonymousHSV3(CircuitNode previous, byte[] keyMaterial) {
		final CircuitNodeCryptoState cs = CircuitNodeCryptoState.createFromHSV3KeyMaterial(keyMaterial);
		return new CircuitNodeImpl(null, previous, cs);
	}
	
	public static CircuitNode createFirstHop(Router r, byte[] keyMaterial, byte[] verifyDigest) {
		return createNode(r, null, keyMaterial, verifyDigest);
	}
	
	public static CircuitNode createNode(Router r, CircuitNode previous, byte[] keyMaterial, byte[] verifyDigest) {
		final CircuitNodeCryptoState cs = CircuitNodeCryptoState.createFromKeyMaterial(keyMaterial, verifyDigest);
		return new CircuitNodeImpl(r, previous, cs);
	}

	final static int CIRCWINDOW_START = 1000;
	final static int CIRCWINDOW_INCREMENT = 100;

	/*
	 * Authenticated SENDMEs (proposal 289; tor-spec, "Flow control").  The
	 * receiver of a group of CIRCWINDOW_INCREMENT RELAY_DATA cells answers
	 * with a version 1 SENDME whose tag is the running digest, at that
	 * point, of the cells it received.  Relays close a circuit on which a
	 * SENDME of a version below the consensus parameter
	 * sendme_accept_min_version (1 on the current network) arrives, except
	 * on a circuit created with CREATE_FAST.
	 */
	final static int SENDME_VERSION_AUTHENTICATED = 1;
	final static int SENDME_TAG_LEN = 20;

	private final Router router;
	private final CircuitNodeCryptoState cryptoState;
	private final CircuitNode previousNode;

	private final Object windowLock;
	private int packageWindow;
	private int deliverWindow;
	/* The tags of the SENDMEs the relay owes us, oldest first */
	private final Queue<byte[]> expectedSendmeTags = new ArrayDeque<byte[]>();
	
	private CircuitNodeImpl(Router router, CircuitNode previous, CircuitNodeCryptoState cryptoState) {
		previousNode = previous;
		this.router = router;
		this.cryptoState = cryptoState;
		windowLock = new Object();
		packageWindow = CIRCWINDOW_START;
		deliverWindow = CIRCWINDOW_START;
	}

	public Router getRouter() {
		return router;
	}

	public CircuitNode getPreviousNode() {
		return previousNode;
	}

	public void encryptForwardCell(RelayCell cell) {
		cryptoState.encryptForwardCell(cell);
	}

	public boolean decryptBackwardCell(Cell cell) {
		return cryptoState.decryptBackwardCell(cell);
	}

	public void updateForwardDigest(RelayCell cell) {
		cryptoState.updateForwardDigest(cell);
	}

	public byte[] getForwardDigestBytes() {
		return cryptoState.getForwardDigestBytes();
	}

	public String toString() {
		if(router != null) {
			return "|"+ router.getNickname() + "|";
		} else {
			return "|()|";
		}
	}

	/**
	 * Whether a DATA cell sent or received when the window had the value
	 * <code>windowBefore</code> is the one a SENDME acknowledges: the last
	 * of each group of CIRCWINDOW_INCREMENT cells.
	 */
	static boolean isSendmeAcknowledgedCell(int windowBefore) {
		return windowBefore > 0 && (windowBefore - 1) % CIRCWINDOW_INCREMENT == 0;
	}

	/** The SENDME tag: the first SENDME_TAG_LEN bytes of a running digest. */
	static byte[] sendmeTag(byte[] digest) {
		return Arrays.copyOf(digest, SENDME_TAG_LEN);
	}

	public byte[] dataCellReceived() {
		synchronized(windowLock) {
			if(deliverWindow <= 0) {
				throw new TorException("Circuit deliver window exceeded on "+ this);
			}
			final boolean due = isSendmeAcknowledgedCell(deliverWindow);
			deliverWindow--;
			if(!due) {
				return null;
			}
			deliverWindow += CIRCWINDOW_INCREMENT;
		}
		return sendmeTag(cryptoState.getBackwardDigestBytes());
	}

	public void waitForSendWindow() {
		synchronized(windowLock) {
			while(packageWindow == 0) {
				try {
					windowLock.wait();
				} catch (InterruptedException e) {
					throw new TorException("Thread interrupted while waiting for circuit send window");
				}
			}
		}
	}

	public int takeSendWindow() {
		synchronized(windowLock) {
			if(packageWindow <= 0) {
				return 0;
			}
			return packageWindow--;
		}
	}

	public void dataCellSent(int sendWindowBefore) {
		if(!isSendmeAcknowledgedCell(sendWindowBefore)) {
			return;
		}
		final byte[] tag = sendmeTag(cryptoState.getForwardDigestBytes());
		synchronized(windowLock) {
			expectedSendmeTags.add(tag);
		}
	}

	public boolean processSendme(byte[] tag) {
		synchronized(windowLock) {
			final byte[] expected = expectedSendmeTags.poll();
			if(expected == null) {
				// A SENDME for cells that were never sent
				return false;
			}
			if(tag != null && !Utils.constantTimeArrayEquals(expected, tag)) {
				return false;
			}
			packageWindow += CIRCWINDOW_INCREMENT;
			windowLock.notifyAll();
			return true;
		}
	}
}
