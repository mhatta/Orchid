package com.subgraph.orchid.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.HexDigest;

public class FallbackDirectoriesTest {

	@Test
	public void testBuiltInListParses() {
		final List<Router> fallbacks = FallbackDirectories.getInstance().getFallbackDirectories();
		assertEquals("every built-in entry should parse",
				FallbackDirectoryList.FALLBACK_DIRECTORIES.length, fallbacks.size());
		assertTrue("fallback list is too short: "+ fallbacks.size(), fallbacks.size() >= 100);
		final Set<HexDigest> identities = new HashSet<HexDigest>();
		for(Router r: fallbacks) {
			assertNotNull(r.getAddress());
			assertTrue(r.getOnionPort() > 0);
			assertTrue(r.isDirectoryCache());
			assertFalse(r.isDirectoryAuthority());
			assertTrue("duplicate fallback "+ r, identities.add(r.getIdentityHash()));
		}
	}

	@Test
	public void testParseEntry() {
		final Router r = FallbackDirectories.parseEntry("192.0.2.7:9001 0123456789ABCDEF0123456789ABCDEF01234567 example");
		assertEquals("example", r.getNickname());
		assertEquals("192.0.2.7", r.getAddress().toString());
		assertEquals(9001, r.getOnionPort());
		assertEquals(HexDigest.createFromString("0123456789ABCDEF0123456789ABCDEF01234567"), r.getIdentityHash());
	}

	@Test
	public void testMalformedEntriesAreSkipped() {
		final FallbackDirectories fd = new FallbackDirectories(new String[] {
				"192.0.2.7:9001 0123456789ABCDEF0123456789ABCDEF01234567 good",
				"192.0.2.8 0123456789ABCDEF0123456789ABCDEF01234567 noport",
				"192.0.2.9:9001 0123 shortid",
		});
		assertEquals(1, fd.getFallbackDirectories().size());
		try {
			FallbackDirectories.parseEntry("192.0.2.9:0 0123456789ABCDEF0123456789ABCDEF01234567");
			fail("port 0 accepted");
		} catch(IllegalArgumentException e) {
			// expected
		}
	}

	private static DirectoryImpl createDirectory(File dataDirectory) {
		final TorConfig config = new TorConfigImpl();
		config.setDataDirectory(dataDirectory);
		return new DirectoryImpl(config, null);
	}

	private static File emptyDataDirectory() throws Exception {
		final File f = File.createTempFile("orchid-test", "");
		f.delete();
		f.mkdirs();
		f.deleteOnExit();
		return f;
	}

	/*
	 * Bootstrap requests should normally go to fallback directories; an
	 * authority is a tenth as likely as each fallback (Tor's
	 * DirAuthorityFallbackRate), which is well under 1% with 200 fallbacks.
	 */
	@Test
	public void testBootstrapPrefersFallbacks() throws Exception {
		final DirectoryImpl directory = createDirectory(emptyDataDirectory());
		int authorities = 0;
		final int n = 5000;
		for(int i = 0; i < n; i++) {
			final Router r = directory.getRandomBootstrapDirectory();
			assertNotNull(r);
			if(r.isDirectoryAuthority()) {
				authorities++;
			}
		}
		assertTrue("authorities chosen "+ authorities +" times out of "+ n, authorities < n / 20);
	}

	/* The bridge authority does not serve the consensus. */
	@Test
	public void testRandomAuthorityIsAV3Authority() throws Exception {
		final DirectoryImpl directory = createDirectory(emptyDataDirectory());
		for(int i = 0; i < 500; i++) {
			final DirectoryServer ds = directory.getRandomDirectoryAuthority();
			assertNotNull(ds + " is not a v3 authority", ds.getV3Identity());
		}
	}
}
