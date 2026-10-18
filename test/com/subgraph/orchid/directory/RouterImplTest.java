package com.subgraph.orchid.directory;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.subgraph.orchid.Directory;
import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.Timestamp;

public class RouterImplTest {
	private static final HexDigest IDENTITY = HexDigest.createFromString("0123456789ABCDEF0123456789ABCDEF01234567");
	private static final HexDigest MD_DIGEST = HexDigest.createFromDigestBytes(new byte[32]);
	private static final HexDigest SD_DIGEST = HexDigest.createFromString("89ABCDEF0123456789ABCDEF0123456789ABCDEF");

	private static RouterStatus status(HexDigest microdescDigest, HexDigest descriptorDigest, Timestamp published) {
		final RouterStatus rs = createNiceMock(RouterStatus.class);
		expect(rs.getIdentity()).andStubReturn(IDENTITY);
		expect(rs.getMicrodescriptorDigest()).andStubReturn(microdescDigest);
		expect(rs.getDescriptorDigest()).andStubReturn(descriptorDigest);
		expect(rs.getPublicationTime()).andStubReturn(published);
		replay(rs);
		return rs;
	}

	private static Directory directory(RouterMicrodescriptor cached) {
		final Directory d = createNiceMock(Directory.class);
		expect(d.getMicrodescriptorFromCache(MD_DIGEST)).andStubReturn(cached);
		replay(d);
		return d;
	}

	private static Timestamp minutesAgo(int minutes) {
		return new Timestamp(new java.util.Date(System.currentTimeMillis() - minutes * 60L * 1000L));
	}

	/*
	 * Since consensus method 33 every "r" line of a microdesc consensus has the
	 * publication time 2038-01-01 00:00:00.  Missing microdescriptors must
	 * still be downloadable, otherwise the client never fetches any.
	 */
	@Test
	public void testMicrodescriptorWithPlaceholderPublicationTimeIsDownloadable() {
		final Timestamp placeholder = Timestamp.createFromDateAndTimeString("2038-01-01 00:00:00");
		final RouterImpl r = RouterImpl.createFromRouterStatus(directory(null), status(MD_DIGEST, null, placeholder));
		assertTrue(r.isDescriptorDownloadable());
	}

	@Test
	public void testCachedMicrodescriptorIsNotDownloadable() {
		final RouterMicrodescriptor md = createNiceMock(RouterMicrodescriptor.class);
		replay(md);
		final Timestamp placeholder = Timestamp.createFromDateAndTimeString("2038-01-01 00:00:00");
		final RouterImpl r = RouterImpl.createFromRouterStatus(directory(md), status(MD_DIGEST, null, placeholder));
		assertFalse(r.isDescriptorDownloadable());
	}

	@Test
	public void testServerDescriptorTenMinuteRule() {
		assertFalse(RouterImpl.createFromRouterStatus(directory(null), status(null, SD_DIGEST, minutesAgo(2))).isDescriptorDownloadable());
		assertTrue(RouterImpl.createFromRouterStatus(directory(null), status(null, SD_DIGEST, minutesAgo(30))).isDescriptorDownloadable());
		/* a publication time in the future is not a real time and must not block the download */
		final Timestamp future = Timestamp.createFromDateAndTimeString("2038-01-01 00:00:00");
		assertTrue(RouterImpl.createFromRouterStatus(directory(null), status(null, SD_DIGEST, future)).isDescriptorDownloadable());
	}
}
