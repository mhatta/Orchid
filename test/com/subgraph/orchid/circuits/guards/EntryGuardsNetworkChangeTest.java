package com.subgraph.orchid.circuits.guards;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * After a network change, guards that could not be reached (most likely
 * because the network was down) are usable again, so that the client does
 * not move to new guards.
 */
public class EntryGuardsNetworkChangeTest {

	private static class FakeGuard implements GuardEntry {
		Date downSince;
		int cleared;
		FakeGuard(Date downSince) { this.downSince = downSince; }
		public boolean isAdded() { return true; }
		public void markAsDown() { downSince = new Date(); }
		public void clearDownSince() { downSince = null; cleared++; }
		public String getNickname() { return "guard"; }
		public String getIdentity() { return "0000000000000000000000000000000000000000"; }
		public String getVersion() { return "0"; }
		public Date getCreatedTime() { return new Date(0); }
		public Date getDownSince() { return downSince; }
		public Date getLastConnectAttempt() { return downSince; }
		public Date getUnlistedSince() { return null; }
		public boolean testCurrentlyUsable() { return true; }
		public Router getRouterForEntry() { return null; }
	}

	@Test
	public void testUnreachableGuardsAreRetried() {
		final FakeGuard down = new FakeGuard(new Date(1000));
		final FakeGuard up = new FakeGuard(null);
		final List<GuardEntry> guards = Arrays.<GuardEntry>asList(down, up);
		final Directory directory = createNiceMock(Directory.class);
		expect(directory.getGuardEntries()).andStubReturn(guards);
		replay(directory);
		final EntryGuards entryGuards = new EntryGuards(new TorConfigImpl(),
				createNiceMock(ConnectionCache.class), createNiceMock(DirectoryDownloader.class), directory);

		entryGuards.networkChanged();

		assertNull(down.getDownSince());
		assertEquals(1, down.cleared);
		assertEquals(0, up.cleared);
	}
}
