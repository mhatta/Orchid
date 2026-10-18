package com.subgraph.orchid.circuits.hs;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.logging.Logger;

/**
 * Selection of the HSDirs responsible for a version 3 onion service
 * descriptor (rend-spec-v3 section 2.2.3 [WHERE-HSDESC], mirroring
 * hs_get_responsible_hsdirs() of the C implementation).
 *
 * Every relay with the HSDir flag is placed on a hash ring at position
 * <pre>
 *   hsdir_index(node) = H("node-idx" | node_identity | shared_random_value | INT_8(period_num) | INT_8(period_length))
 * </pre>
 * and for each replica the service's position is
 * <pre>
 *   hs_index(replicanum) = H("store-at-idx" | blinded_public_key | INT_8(replicanum) | INT_8(period_length) | INT_8(period_num))
 * </pre>
 * A client fetches from any of the first <code>hsdir_spread_fetch</code>
 * nodes following each hs_index.
 */
public class HSV3Directories {
	private static final Logger logger = Logger.getInstance(HSV3Directories.class);

	private final Directory directory;
	private final TorRandom random = new TorRandom();

	private ConsensusDocument indexedConsensus;
	private byte[] indexedSrv;
	private long indexedPeriod;
	private List<IndexedRouter> ring = new ArrayList<IndexedRouter>();

	private static final class IndexedRouter {
		final Router router;
		final byte[] index;
		IndexedRouter(Router router, byte[] index) {
			this.router = router;
			this.index = index;
		}
	}

	public HSV3Directories(Directory directory) {
		this.directory = directory;
	}

	/**
	 * Return the HSDirs a client should try, in random order within each
	 * replica, for the service with the given blinded key in the given time
	 * period.  Returns an empty list if no consensus is available.
	 */
	public synchronized List<Router> getResponsibleDirectories(byte[] blindedPublicKey, HSV3TimePeriod timePeriod) {
		final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
		if(consensus == null) {
			logger.warn("No consensus available to compute v3 hidden service directories");
			return Collections.emptyList();
		}
		final byte[] srv = timePeriod.selectFetchSharedRandomValue(consensus);
		refreshRing(consensus, srv, timePeriod);
		if(ring.isEmpty()) {
			logger.warn("No HSDir relays with an ed25519 identity found in consensus");
			return Collections.emptyList();
		}
		final int nReplicas = consensus.getHSDirNReplicasParameter();
		final int spreadFetch = consensus.getHSDirSpreadFetchParameter();
		final List<Router> result = new ArrayList<Router>();
		for(int replica = 1; replica <= nReplicas; replica++) {
			final byte[] hsIndex = HSV3Crypto.hsIndex(replica, blindedPublicKey, timePeriod.getPeriodLengthMinutes(), timePeriod.getPeriodNumber());
			final List<Router> forReplica = new ArrayList<Router>(spreadFetch);
			int idx = firstIndexAtOrAfter(hsIndex);
			final int start = idx;
			while(forReplica.size() < spreadFetch) {
				final Router r = ring.get(idx).router;
				if(!result.contains(r) && !forReplica.contains(r)) {
					forReplica.add(r);
				}
				idx = (idx + 1) % ring.size();
				if(idx == start) {
					break;
				}
			}
			shuffle(forReplica);
			result.addAll(forReplica);
		}
		return result;
	}

	private void refreshRing(ConsensusDocument consensus, byte[] srv, HSV3TimePeriod timePeriod) {
		if(consensus == indexedConsensus && java.util.Arrays.equals(srv, indexedSrv) && timePeriod.getPeriodNumber() == indexedPeriod) {
			return;
		}
		final List<IndexedRouter> newRing = new ArrayList<IndexedRouter>();
		for(Router r: directory.getAllRouters()) {
			if(!r.isHSDirectory()) {
				continue;
			}
			final byte[] ed = r.getEd25519Identity();
			if(ed == null) {
				continue;
			}
			newRing.add(new IndexedRouter(r, HSV3Crypto.hsdirIndex(ed, srv, timePeriod.getPeriodNumber(), timePeriod.getPeriodLengthMinutes())));
		}
		Collections.sort(newRing, new Comparator<IndexedRouter>() {
			public int compare(IndexedRouter a, IndexedRouter b) {
				return compareUnsigned(a.index, b.index);
			}
		});
		ring = newRing;
		indexedConsensus = consensus;
		indexedSrv = srv;
		indexedPeriod = timePeriod.getPeriodNumber();
		logger.debug("Built v3 HSDir hash ring with "+ ring.size() + " relays for "+ timePeriod);
	}

	/** Index of the first ring entry whose hsdir_index is >= the given value (wrapping to 0). */
	private int firstIndexAtOrAfter(byte[] value) {
		int lo = 0, hi = ring.size();
		while(lo < hi) {
			final int mid = (lo + hi) >>> 1;
			if(compareUnsigned(ring.get(mid).index, value) < 0) {
				lo = mid + 1;
			} else {
				hi = mid;
			}
		}
		return (lo == ring.size()) ? 0 : lo;
	}

	static int compareUnsigned(byte[] a, byte[] b) {
		final int n = Math.min(a.length, b.length);
		for(int i = 0; i < n; i++) {
			final int x = a[i] & 0xFF;
			final int y = b[i] & 0xFF;
			if(x != y) {
				return x - y;
			}
		}
		return a.length - b.length;
	}

	private void shuffle(List<Router> list) {
		for(int i = list.size() - 1; i > 0; i--) {
			final int j = random.nextInt(i + 1);
			final Router tmp = list.get(i);
			list.set(i, list.get(j));
			list.set(j, tmp);
		}
	}
}
