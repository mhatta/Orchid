package com.subgraph.orchid.crypto;

import static org.junit.Assert.fail;

import org.junit.Test;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.data.HexDigest;

/**
 * A CREATED2 or EXTENDED2 reply of the wrong length is refused with a
 * TorException; it used to end in a BufferUnderflowException.
 */
public class TorNTorKeyAgreementTest {

	private static TorNTorKeyAgreement agreement() {
		final HexDigest identity = HexDigest.createFromDigestBytes(new byte[20]);
		final byte[] onionKey = new byte[32];
		onionKey[0] = 9;
		final TorNTorKeyAgreement kex = new TorNTorKeyAgreement(identity, onionKey);
		kex.createOnionSkin();
		return kex;
	}

	private static void refused(byte[] reply) {
		try {
			agreement().deriveKeysFromHandshakeResponse(reply, new byte[72], new byte[20]);
			fail("a reply of "+ ((reply == null) ? "null" : reply.length +" bytes") +" was accepted");
		} catch(TorException e) {
			// expected
		}
	}

	@Test
	public void testShortReplyRefused() {
		refused(new byte[0]);
		refused(new byte[63]);
	}

	@Test
	public void testLongReplyRefused() {
		refused(new byte[65]);
	}

	@Test
	public void testNullReplyRefused() {
		refused(null);
	}
}
