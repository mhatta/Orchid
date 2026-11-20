package com.subgraph.orchid.directory.downloader;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
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
	 * A descriptor is asked for again, if it is still missing, after 15
	 * seconds, then after twice as long each time, up to the ten minutes
	 * between ordinary downloads (dir-spec 5.3; Tor keeps a download
	 * status with an exponential backoff for each descriptor too).
	 */
	private final static long RETRY_INITIAL = 15 * 1000;
	private final static long RETRY_MAX = MAX_CLIENT_INTERVAL_WITHOUT_REQUEST;

	private final TorConfig config;
	private final Directory directory;
	
	private Date lastDescriptorDownload;

	/* Descriptor digest -> how often it was asked for, and when it may be asked for again. */
	private static final class Attempts {
		int count;
		long notBefore;
	}
	private final Map<HexDigest, Attempts> attempts = new HashMap<HexDigest, Attempts>();
	
	
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

	/*
	 * The missing descriptors that may be asked for now: those never asked
	 * for, and those whose wait after the last attempt is over.  The
	 * attempts of descriptors that are no longer missing (they arrived, or
	 * a new consensus replaced them) are forgotten, so a descriptor that
	 * goes missing again starts afresh.
	 */
	private List<Router> getEligible(List<Router> downloadables) {
		final long now = clock.now();
		final Set<HexDigest> missing = new HashSet<HexDigest>();
		final List<Router> eligible = new ArrayList<Router>();
		for(Router r: downloadables) {
			final HexDigest d = getDescriptorDigestForRouter(r);
			missing.add(d);
			final Attempts a = attempts.get(d);
			if(a == null || now >= a.notBefore) {
				eligible.add(r);
			}
		}
		for(Iterator<HexDigest> it = attempts.keySet().iterator(); it.hasNext();) {
			if(!missing.contains(it.next())) {
				it.remove();
			}
		}
		return eligible;
	}

	private void recordAttempts(List<Router> routers) {
		final long now = clock.now();
		for(Router r: routers) {
			final HexDigest d = getDescriptorDigestForRouter(r);
			Attempts a = attempts.get(d);
			if(a == null) {
				a = new Attempts();
				attempts.put(d, a);
			}
			a.count++;
			final int doublings = Math.min(a.count - 1, 16);
			a.notBefore = now + Math.min(RETRY_INITIAL << doublings, RETRY_MAX);
		}
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

	/*
	 * After a network change the failures say nothing about the new
	 * network: without this, a phone that was offline for a while waited
	 * up to ten more minutes, once back online, for the descriptor of its
	 * primary guard.
	 */
	synchronized void networkChanged() {
		attempts.clear();
	}

	synchronized List< List<HexDigest> > getDescriptorDigestsToDownload() {
		final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		if(consensus == null || !consensus.isLive()) {
			return Collections.emptyList();
		}
		final List<Router> downloadables = getEligible(directory.getRoutersWithDownloadableDescriptors());
		if(canDownloadDescriptors(downloadables.size())) {
			lastDescriptorDownload = new Date(clock.now());
			recordAttempts(downloadables);
			return partitionDescriptors(downloadables);
		}
		final List<Router> requested = getRequestedNow(downloadables);
		if(!requested.isEmpty()) {
			/*
			 * A descriptor a circuit is waiting for (a primary guard's):
			 * download it now, not when 16 are missing or 10 minutes have
			 * passed.  Only the requested descriptors are fetched.  Each
			 * try goes through a directory guard chosen again, so a guard
			 * that withholds the descriptor does not keep it away.
			 */
			recordAttempts(requested);
			return partitionDescriptors(requested);
		}
		return Collections.emptyList();
	}
}
