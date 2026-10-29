package com.subgraph.orchid.circuits.path;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * Country codes in node filters must not be silently ignored when there
 * is no geoip database: ExcludeNodes {ru} would then exclude nothing.
 */
public class TorConfigNodeFilterCountryCodeTest {

	private static void assertRefused(TorConfig config, String... names) {
		try {
			TorConfigNodeFilter.checkCountryCodes(config, false);
			fail("configuration accepted without a geoip database");
		} catch(TorException e) {
			for(String name: names) {
				assertTrue(e.getMessage(), e.getMessage().contains(name));
			}
		}
	}

	@Test
	public void testExcludeNodesCountryWithoutDatabaseIsRefused() {
		final TorConfig config = new TorConfigImpl();
		config.setExcludeNodes(Arrays.asList("1.2.3.0/24", "{ru}"));
		assertRefused(config, "ExcludeNodes {ru}");
	}

	@Test
	public void testEveryOptionIsChecked() {
		final TorConfig config = new TorConfigImpl();
		config.setExcludeExitNodes(Arrays.asList("{cn}"));
		config.setEntryNodes(Arrays.asList("{se}"));
		config.setExitNodes(Arrays.asList("{DE}", "{nl}"));
		assertRefused(config, "ExcludeExitNodes {cn}", "EntryNodes {se}", "ExitNodes {DE}", "ExitNodes {nl}");
	}

	@Test
	public void testCountryCodesWithDatabaseAreAccepted() {
		final TorConfig config = new TorConfigImpl();
		config.setExcludeNodes(Arrays.asList("{ru}"));
		config.setExitNodes(Arrays.asList("{de}"));
		TorConfigNodeFilter.checkCountryCodes(config, true);
	}

	@Test
	public void testOtherEntriesWithoutDatabaseAreAccepted() {
		final TorConfig config = new TorConfigImpl();
		config.setExcludeNodes(Arrays.asList("1.2.3.0/24", "badrelay", "{??}"));
		config.setExitNodes(Arrays.asList("0123456789ABCDEF0123456789ABCDEF01234567"));
		TorConfigNodeFilter.checkCountryCodes(config, false);
		TorConfigNodeFilter.checkCountryCodes(new TorConfigImpl(), false);
	}
}
