package com.subgraph.orchid.directory;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Date;

import org.junit.Test;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.data.Timestamp;

/**
 * A consensus is used only from a day before its valid-after time until a
 * day after its valid-until time, as in Tor.  It used to be accepted at
 * any time as long as its signatures were good.
 */
public class ConsensusFreshnessTest {
	private static final long HOUR = 60 * 60 * 1000L;
	private static final long NOW = 1800000000000L;

	private static ConsensusDocument consensus(long validAfter, long validUntil) {
		final ConsensusDocument c = createMock(ConsensusDocument.class);
		expect(c.getValidAfterTime()).andStubReturn(new Timestamp(new Date(validAfter)));
		expect(c.getValidUntilTime()).andStubReturn(new Timestamp(new Date(validUntil)));
		replay(c);
		return c;
	}

	@Test
	public void testCurrentConsensusIsLive() {
		assertTrue(DirectoryImpl.isReasonablyLive(consensus(NOW - HOUR, NOW + 2 * HOUR), NOW));
	}

	@Test
	public void testRecentlyExpiredConsensusIsStillUsable() {
		assertTrue(DirectoryImpl.isReasonablyLive(consensus(NOW - 26 * HOUR, NOW - 23 * HOUR), NOW));
	}

	@Test
	public void testOldConsensusIsRejected() {
		assertFalse(DirectoryImpl.isReasonablyLive(consensus(NOW - 28 * HOUR, NOW - 25 * HOUR), NOW));
		assertFalse(DirectoryImpl.isReasonablyLive(consensus(NOW - 365 * 24 * HOUR, NOW - 365 * 24 * HOUR + 3 * HOUR), NOW));
	}

	@Test
	public void testConsensusFromTheFutureIsRejected() {
		assertTrue(DirectoryImpl.isReasonablyLive(consensus(NOW + 23 * HOUR, NOW + 26 * HOUR), NOW));
		assertFalse(DirectoryImpl.isReasonablyLive(consensus(NOW + 25 * HOUR, NOW + 28 * HOUR), NOW));
	}

	@Test
	public void testConsensusWithoutTimesIsRejected() {
		final ConsensusDocument c = createMock(ConsensusDocument.class);
		expect(c.getValidAfterTime()).andStubReturn(null);
		expect(c.getValidUntilTime()).andStubReturn(null);
		replay(c);
		assertFalse(DirectoryImpl.isReasonablyLive(c, NOW));
	}
}
