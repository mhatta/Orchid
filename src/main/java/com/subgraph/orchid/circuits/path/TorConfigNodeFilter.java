package com.subgraph.orchid.circuits.path;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.geoip.CountryCodeService;

public class TorConfigNodeFilter {
	
	/* 
	 * Even though these are exactly the configuration file variable names, they are only
	 * used here as keys into a Map<String,ConfigNodeFilter>
	 */
	private final static String EXCLUDE_NODES_FILTER = "ExcludeNodes";
	private final static String EXCLUDE_EXIT_NODES_FILTER = "ExcludeExitNodes";
	private final static String ENTRY_NODES_FILTER = "EntryNodes";
	private final static String EXIT_NODES_FILTER = "ExitNodes";
	
	private final Map<String, ConfigNodeFilter> filters;
	
	TorConfigNodeFilter(TorConfig config) {
		this.filters = new HashMap<String, ConfigNodeFilter>();
		addFilter(filters, EXCLUDE_NODES_FILTER, config.getExcludeNodes());
		addFilter(filters, EXCLUDE_EXIT_NODES_FILTER, config.getExcludeExitNodes());
		addFilter(filters, ENTRY_NODES_FILTER, config.getEntryNodes());
		addFilter(filters, EXIT_NODES_FILTER, config.getExitNodes());
	}
	
	/**
	 * Refuse a configuration whose node filters name countries when there
	 * is no geoip database.  Without one every relay's country is
	 * {@value CountryCodeService#UNKNOWN}, so <code>ExcludeNodes {ru}</code>
	 * would exclude nothing and the relays the user meant to avoid would
	 * be used, and <code>ExitNodes {de}</code> would leave no exit at all.
	 * The country code {@value CountryCodeService#UNKNOWN} itself works
	 * without a database and is allowed.
	 *
	 * @throws TorException naming the options and entries that need the database
	 */
	public static void checkCountryCodes(TorConfig config) {
		checkCountryCodes(config, CountryCodeService.getInstance().isAvailable());
	}

	static void checkCountryCodes(TorConfig config, boolean geoipAvailable) {
		if(geoipAvailable) {
			return;
		}
		final List<String> entries = new ArrayList<String>();
		addCountryCodeEntries(entries, EXCLUDE_NODES_FILTER, config.getExcludeNodes());
		addCountryCodeEntries(entries, EXCLUDE_EXIT_NODES_FILTER, config.getExcludeExitNodes());
		addCountryCodeEntries(entries, ENTRY_NODES_FILTER, config.getEntryNodes());
		addCountryCodeEntries(entries, EXIT_NODES_FILTER, config.getExitNodes());
		if(entries.isEmpty()) {
			return;
		}
		final StringBuilder sb = new StringBuilder();
		for(String e: entries) {
			if(sb.length() > 0) {
				sb.append(", ");
			}
			sb.append(e);
		}
		throw new TorException("Country codes in node filters need a geoip database, and none was found: "+ sb
				+ ".  Install one (see "+ CountryCodeService.class.getName() +") or remove these entries.");
	}

	private static void addCountryCodeEntries(List<String> entries, String name, List<String> filterStrings) {
		if(filterStrings == null) {
			return;
		}
		for(String s: filterStrings) {
			if(ConfigNodeFilter.isCountryCodeString(s) && !s.equals("{"+ CountryCodeService.UNKNOWN +"}")) {
				entries.add(name +" "+ s);
			}
		}
	}

	private static void addFilter(Map<String, ConfigNodeFilter> filters, String name, List<String> filterStrings) {
		if(filterStrings == null || filterStrings.isEmpty()) {
			return;
		}
		filters.put(name, ConfigNodeFilter.createFromStrings(filterStrings));
	}
	
	List<Router> filterExitCandidates(List<Router> candidates) {
		final List<Router> filtered = new ArrayList<Router>();
		for(Router r: candidates) {
			if(isExitNodeIncluded(r)) {
				filtered.add(r);
			}
		}
		return filtered;
	}

	boolean isExitNodeIncluded(Router exitRouter) {
		return isIncludedByFilter(exitRouter, EXIT_NODES_FILTER) && 
				!(isExcludedByFilter(exitRouter, EXCLUDE_EXIT_NODES_FILTER) || 
						isExcludedByFilter(exitRouter, EXCLUDE_NODES_FILTER));
	}
	
	boolean isIncludedByFilter(Router r, String filterName) {
		final ConfigNodeFilter f = filters.get(filterName);
		if(f == null || f.isEmpty()) {
			return true;
		}
		return f.filter(r);
	}
	
	boolean isExcludedByFilter(Router r, String filterName) {
		final ConfigNodeFilter f = filters.get(filterName);
		if(f == null || f.isEmpty()) {
			return false;
		}
		return f.filter(r);
	}
}
