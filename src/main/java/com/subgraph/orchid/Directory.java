package com.subgraph.orchid;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.subgraph.orchid.ConsensusDocument.RequiredCertificate;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.events.EventHandler;

/**
 * 
 * Main interface for accessing directory information and interacting
 * with directory authorities and caches.
 *
 */
public interface Directory {
	boolean haveMinimumRouterInfo();
	void loadFromStore();
	void close();
	void waitUntilLoaded();
	void storeCertificates();
	
	Collection<DirectoryServer> getDirectoryAuthorities();
	DirectoryServer getRandomDirectoryAuthority();
	/**
	 * Choose a directory to use when no directory cache is known from a
	 * consensus: usually a fallback directory, occasionally an authority.
	 */
	Router getRandomBootstrapDirectory();
	void addCertificate(KeyCertificate certificate);
	Set<RequiredCertificate> getRequiredCertificates();
	void addRouterMicrodescriptors(List<RouterMicrodescriptor> microdescriptors);
	void addRouterDescriptors(List<RouterDescriptor> descriptors);
	void addConsensusDocument(ConsensusDocument consensus, boolean fromCache);
	ConsensusDocument getCurrentConsensusDocument();
	boolean hasPendingConsensus();
	void registerConsensusChangedHandler(EventHandler handler);
	void unregisterConsensusChangedHandler(EventHandler handler);
	Router getRouterByName(String name);
	Router getRouterByIdentity(HexDigest identity);
	List<Router> getRouterListByNames(List<String> names);
	List<Router> getRoutersWithDownloadableDescriptors();
	List<Router> getAllRouters();
	
	RouterMicrodescriptor getMicrodescriptorFromCache(HexDigest descriptorDigest);
	RouterDescriptor getBasicDescriptorFromCache(HexDigest descriptorDigest);
	
	/**
	 * The sampled entry guards as kept in the state file, in order: one
	 * map of the fields of each <code>Guard</code> line (guard-spec,
	 * "Persistent state format").  EntryGuards gives them their meaning.
	 */
	List<Map<String, String>> getGuardState();

	/** Replace the sampled entry guards in the state file and write it. */
	void setGuardState(List<Map<String, String>> guards);
}
