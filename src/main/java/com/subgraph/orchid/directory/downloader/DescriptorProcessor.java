package com.subgraph.orchid.directory.downloader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.AutoBoolValue;
import com.subgraph.orchid.data.HexDigest;

public class DescriptorProcessor {
	private final static int MAX_DL_PER_REQUEST = 96;
	private final static int MAX_DL_TO_DELAY = 16;
	private final static int MIN_DL_REQUESTS = 3;
	private final static int MAX_CLIENT_INTERVAL_WITHOUT_REQUEST = 10 * 60 * 1000;
	/*
	 * A download asked for with Directory.requestDescriptorsNow() is tried
	 * again after 15 seconds, then after twice as long each time it fails,
	 * up to the ten minutes between ordinary downloads.
	 */
	private final static long URGENT_RETRY_INITIAL = 15 * 1000;
	private final static long URGENT_RETRY_MAX = MAX_CLIENT_INTERVAL_WITHOUT_REQUEST;

	private final TorConfig config;
	private final Directory directory;
	
	private Date lastDescriptorDownload;
	private long lastUrgentDownload = Long.MIN_VALUE;
	private long urgentRetryInterval = URGENT_RETRY_INITIAL;
	/* Identities whose descriptors the last urgent download asked for. */
	private Set<HexDigest> lastUrgentIdentities = new HashSet<HexDigest>();
	
	
	/* Milliseconds since the epoch; replaced in tests. */
	interface Clock {
		long now();
	}

	private final Clock clock;

	DescriptorProcessor(TorConfig config, Directory directory) {
		this(config, directory, new Clock() {
			public long now() {
				return System.currentTimeMillis();
			}
		});
	}

	DescriptorProcessor(TorConfig config, Directory directory, Clock clock) {
		this.config = config;
		this.directory = directory;
		this.clock = clock;
	}

	private boolean canDownloadDescriptors(int downloadableCount) {
		if(downloadableCount >= MAX_DL_TO_DELAY)
			return true;
		if(downloadableCount == 0)
			return false;
		if(lastDescriptorDownload == null)
			return true;
		final long diff = clock.now() - lastDescriptorDownload.getTime();
		return diff > MAX_CLIENT_INTERVAL_WITHOUT_REQUEST;
	}

	/* The routers among downloadables whose descriptors were asked for with requestDescriptorsNow(). */
	private List<Router> getRequestedNow(List<Router> downloadables) {
		final Set<HexDigest> wanted = directory.getDescriptorsRequestedNow();
		final List<Router> requested = new ArrayList<Router>();
		if(wanted == null || wanted.isEmpty()) {
			return requested;
		}
		for(Router r: downloadables) {
			if(wanted.contains(r.getIdentityHash())) {
				requested.add(r);
			}
		}
		return requested;
	}

	private static Set<HexDigest> identitiesOf(List<Router> routers) {
		final Set<HexDigest> ids = new HashSet<HexDigest>();
		for(Router r: routers) {
			ids.add(r.getIdentityHash());
		}
		return ids;
	}

	/* True if some requested descriptor has not been asked for since it was requested. */
	private boolean hasNewRequest(List<Router> requested) {
		return !lastUrgentIdentities.containsAll(identitiesOf(requested));
	}

	private boolean isUrgentDue(List<Router> requested) {
		if(requested.isEmpty()) {
			return false;
		}
		if(lastUrgentDownload == Long.MIN_VALUE || hasNewRequest(requested)) {
			return true;
		}
		return clock.now() - lastUrgentDownload >= urgentRetryInterval;
	}

	/* Called each time a download includes the requested descriptors. */
	private void recordUrgentDownload(List<Router> requested) {
		if(lastUrgentDownload == Long.MIN_VALUE || hasNewRequest(requested)) {
			urgentRetryInterval = URGENT_RETRY_INITIAL;
		} else {
			urgentRetryInterval = Math.min(urgentRetryInterval * 2, URGENT_RETRY_MAX);
		}
		lastUrgentDownload = clock.now();
		lastUrgentIdentities = identitiesOf(requested);
	}

	private void resetUrgent() {
		lastUrgentDownload = Long.MIN_VALUE;
		urgentRetryInterval = URGENT_RETRY_INITIAL;
		lastUrgentIdentities = new HashSet<HexDigest>();
	}

	/*
	 * dir-spec.txt section 5.3
	 */
	private List< List<HexDigest> > partitionDescriptors(List<Router> descriptors) {
		final int size = descriptors.size();
		final List< List<HexDigest> > partitions = new ArrayList< List<HexDigest> >();
		if(size <= 10) {
			partitions.add(createPartitionList(descriptors, 0, size));
			return partitions;
		} else if(size <= (MIN_DL_REQUESTS * MAX_DL_PER_REQUEST)) {
			final int chunk = size / MIN_DL_REQUESTS;
			int over = size % MIN_DL_REQUESTS;
			int off = 0;
			for(int i = 0; i < MIN_DL_REQUESTS; i++) {
				int sz = chunk;
				if(over != 0) {
					sz++;
					over--;
				}
				partitions.add(createPartitionList(descriptors, off, sz));
				off += sz;
			}
			return partitions;
			
		} else {
			int off = 0;
			while(off < descriptors.size()) {
				partitions.add(createPartitionList(descriptors, off, MAX_DL_PER_REQUEST));
				off += MAX_DL_PER_REQUEST;
			}
			return partitions;	
		}
	}

	private List<HexDigest> createPartitionList(List<Router> descriptors, int offset, int size) {
		final List<HexDigest> newList = new ArrayList<HexDigest>();
		for(int i = offset; i < (offset + size) && i < descriptors.size(); i++) {
			final HexDigest digest = getDescriptorDigestForRouter(descriptors.get(i));
			newList.add(digest);
		}
		return newList;
	}

	private HexDigest getDescriptorDigestForRouter(Router r) {
		if(useMicrodescriptors()) {
			return r.getMicrodescriptorDigest();
		} else {
			return r.getDescriptorDigest();
		}
	}
	
	private boolean useMicrodescriptors() {
		return config.getUseMicrodescriptors() != AutoBoolValue.FALSE;
	}

	List< List<HexDigest> > getDescriptorDigestsToDownload() {
		final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		if(consensus == null || !consensus.isLive()) {
			return Collections.emptyList();
		}
		final List<Router> downloadables = directory.getRoutersWithDownloadableDescriptors();
		final List<Router> requested = getRequestedNow(downloadables);
		if(requested.isEmpty()) {
			resetUrgent();
		}
		if(canDownloadDescriptors(downloadables.size())) {
			if(!requested.isEmpty()) {
				recordUrgentDownload(requested);
			}
			lastDescriptorDownload = new Date(clock.now());
			return partitionDescriptors(downloadables);
		}
		if(isUrgentDue(requested)) {
			/*
			 * A descriptor a circuit is waiting for (a primary guard's):
			 * download it now, not when 16 are missing or 10 minutes have
			 * passed. Only the requested descriptors are fetched, and a
			 * descriptor that stays missing is tried again after 15
			 * seconds, then 30, 60 and so on up to 10 minutes. Each try
			 * goes through a directory guard chosen again, so a guard that
			 * withholds the descriptor does not keep it away.
			 */
			recordUrgentDownload(requested);
			return partitionDescriptors(requested);
		}
		return Collections.emptyList();
	}
}
