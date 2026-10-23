package com.subgraph.orchid;



/**
 * Represents the state of a single onion router hop in a connected or connecting {@link Circuit}
 */
public interface CircuitNode {
	/**
	 * Return the {@link Router} associated with this node.
	 *
	 * @return The {@link Router} for this hop of the circuit chain.
	 */
	Router getRouter();

	/**
	 * Update the 'forward' cryptographic digest state for this
	 * node with the contents of <code>cell</code>
	 * 
	 * @param cell The {@link RelayCell} to add to the digest.
	 */
	void updateForwardDigest(RelayCell cell);

	/**
	 * Return the current 'forward' running digest value for this 
	 * node as an array of <code>TOR_DIGEST_SIZE</code> bytes.
	 * 
	 * @return The current 'forward' running digest value for this node.
	 */
	byte[] getForwardDigestBytes();

	/**
	 * Encrypt a {@link RelayCell} for this node with the current
	 * 'forward' cipher state.
	 * 
	 * @param cell The {@link RelayCell} to encrypt.
	 */
	void encryptForwardCell(RelayCell cell);

	/**
	 * Return the {@link CircuitNode} which immediately preceeds this
	 * one in the circuit node chain or <code>null</code> if this is
	 * the first hop.
	 * 
	 * @return The previous {@link CircuitNode} in the chain or <code>
	 *         null</code> if this is the first node.
	 */
	CircuitNode getPreviousNode();

	/**
	 * Return immediately if the packaging window for this node is open (ie: greater than 0), otherwise
	 * block until the circuit is destroyed or the window is incremented by receiving a RELAY_SENDME cell
	 * from this node.
	 */
	void waitForSendWindow();

	/**
	 * If the packaging window for this node is open (ie: greater than 0),
	 * decrement it by one and return the value it had before; otherwise
	 * return 0 without changing it.  Call {@link #waitForSendWindow()} to
	 * wait for the window to open.
	 *
	 * @return The packaging window before it was decremented, or 0 if it
	 *         was closed.
	 */
	int takeSendWindow();

	/**
	 * Called right after a RELAY_DATA cell has been added to the 'forward'
	 * digest of this node, with the value {@link #takeSendWindow()} returned
	 * for it.  If the relay will acknowledge this cell with a SENDME, its
	 * digest is remembered so that the authenticated SENDME can be checked.
	 */
	void dataCellSent(int sendWindowBefore);

	/**
	 * Process a circuit level RELAY_SENDME cell received from this node:
	 * check its authentication tag and, if it is acceptable, open the
	 * packaging window by one increment and wake up the threads waiting for
	 * it.
	 *
	 * @param tag The tag of a version 1 (authenticated) SENDME, or null for
	 *            a version 0 SENDME.
	 * @return false if the SENDME acknowledges no cell that was sent or its
	 *         tag does not match, in which case the circuit must be closed.
	 */
	boolean processSendme(byte[] tag);

	/**
	 * Called when a RELAY_DATA cell has been received from this node, right
	 * after it was added to the 'backward' digest.  Decrements the deliver
	 * window and, if it is time to send a circuit level SENDME, increments
	 * it again and returns the tag to put in the authenticated SENDME: the
	 * running digest of the cells received from this node.
	 *
	 * @return The SENDME tag if a SENDME must be sent now, otherwise null.
	 */
	byte[] dataCellReceived();

	boolean decryptBackwardCell(Cell cell);
}
