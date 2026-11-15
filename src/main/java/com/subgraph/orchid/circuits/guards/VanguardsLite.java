package com.subgraph.orchid.circuits.guards;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser.WeightRule;
import com.subgraph.orchid.circuits.path.RouterFilter;
import com.subgraph.orchid.circuits.path.TorConfigNodeFilter;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.logging.Logger;

/**
 * Layer-2 guards for onion service circuits, as in Tor's vanguards-lite
 * (proposal 333, on by default since Tor 0.4.7).
 *
 * Without them the second hop of an onion service circuit is a fresh
 * middle relay each time, and an attacker who can make a client build many
 * such circuits (by asking for an onion service, or by being the service)
 * soon gets a relay of its own next to the client's guard and learns which
 * guard it is.  With vanguards-lite the second hop of every onion service
 * circuit is one of a small set of relays ({@value #DEFAULT_NUM_LAYER2}),
 * each kept for one to twelve days (the larger of two uniform draws, so
 * about a week on average):
 *
 * <pre>
 * rendezvous:          C - Guard - L2 - Rend
 * introduction, HSDir: C - Guard - L2 - M - Intro / HSDir
 * </pre>
 *
 * As in Tor, the set is kept in memory only and starts afresh with every
 * run.  The consensus parameters guard-hs-l2-number,
 * guard-hs-l2-lifetime-min and guard-hs-l2-lifetime-max override the
 * defaults.
 */
public class VanguardsLite {
    private static final Logger logger = Logger.getInstance(VanguardsLite.class);

    static final int DEFAULT_NUM_LAYER2 = 4;
    static final int MAX_NUM_LAYER2 = 19;
    static final long DEFAULT_LIFETIME_MIN = TimeUnit.DAYS.toMillis(1);
    static final long DEFAULT_LIFETIME_MAX = TimeUnit.DAYS.toMillis(12);

    private static final class Layer2 {
        final HexDigest identity;
        final long expires;
        Layer2(HexDigest identity, long expires) {
            this.identity = identity;
            this.expires = expires;
        }
    }

    private final Directory directory;
    private final CircuitNodeChooser nodeChooser;
    private final TorConfigNodeFilter configFilter;
    private final TorRandom random = new TorRandom();
    private final EntryGuards.Clock clock;
    private final List<Layer2> layer2 = new ArrayList<Layer2>();

    public VanguardsLite(TorConfig config, Directory directory) {
        this(config, directory, new CircuitNodeChooser(config, directory), new EntryGuards.Clock() {
            public long now() {
                return System.currentTimeMillis();
            }
        });
    }

    VanguardsLite(TorConfig config, Directory directory, CircuitNodeChooser nodeChooser, EntryGuards.Clock clock) {
        this.directory = directory;
        this.nodeChooser = nodeChooser;
        this.configFilter = new TorConfigNodeFilter(config);
        this.clock = clock;
    }

    /**
     * A layer-2 guard for the second hop of an onion service circuit, not in
     * excluded (the guard and its relatives), or null if none of the current
     * layer-2 guards may be used with this guard.
     */
    public synchronized Router chooseLayer2(Set<Router> excluded) {
        maintain();
        final List<Router> candidates = new ArrayList<Router>();
        for(Layer2 l: layer2) {
            final Router r = directory.getRouterByIdentity(l.identity);
            if(r != null && !excluded.contains(r)) {
                candidates.add(r);
            }
        }
        if(candidates.isEmpty()) {
            return null;
        }
        return candidates.get(random.nextInt(candidates.size()));
    }

    /* Drop expired and no longer usable layer-2 guards; fill up to the wanted number. */
    synchronized void maintain() {
        final long now = clock.now();
        for(Iterator<Layer2> it = layer2.iterator(); it.hasNext(); ) {
            final Layer2 l = it.next();
            final Router r = directory.getRouterByIdentity(l.identity);
            if(now >= l.expires || !isUsable(r)) {
                it.remove();
            }
        }
        final int wanted = param("guard-hs-l2-number", DEFAULT_NUM_LAYER2, 1, MAX_NUM_LAYER2);
        while(layer2.size() > wanted) {
            layer2.remove(layer2.size() - 1);
        }
        while(layer2.size() < wanted) {
            final Router r = nodeChooser.chooseRandomNode(WeightRule.WEIGHT_FOR_MID, new RouterFilter() {
                public boolean filter(Router router) {
                    return isUsable(router) && !contains(router);
                }
            });
            if(r == null) {
                logger.debug("No relay available as a layer-2 guard");
                return;
            }
            layer2.add(new Layer2(r.getIdentityHash(), now + lifetime()));
        }
    }

    /* Like Tor's vanguards: Fast and Stable relays, allowed by ExcludeNodes. */
    private boolean isUsable(Router r) {
        return r != null && r.isValid() && r.isRunning() && r.isFast() && r.isStable()
                && r.getCurrentDescriptor() != null && configFilter.isAllowedOnCircuit(r);
    }

    private boolean contains(Router r) {
        for(Layer2 l: layer2) {
            if(l.identity.equals(r.getIdentityHash())) {
                return true;
            }
        }
        return false;
    }

    /* max(X, Y) with X and Y uniform in [min, max]: the vanguards-lite lifetime. */
    private long lifetime() {
        final long min = param("guard-hs-l2-lifetime-min", (int) (DEFAULT_LIFETIME_MIN / 1000), 1, Integer.MAX_VALUE) * 1000L;
        final long max = Math.max(min, param("guard-hs-l2-lifetime-max", (int) (DEFAULT_LIFETIME_MAX / 1000), 1, Integer.MAX_VALUE) * 1000L);
        final long span = max - min;
        if(span <= 0) {
            return min;
        }
        final long a = random.nextLong(span + 1);
        final long b = random.nextLong(span + 1);
        return min + Math.max(a, b);
    }

    private int param(String name, int defaultValue, int min, int max) {
        final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
        return (consensus == null) ? defaultValue : consensus.getIntegerParameter(name, defaultValue, min, max);
    }

    /* For tests */
    synchronized List<HexDigest> getLayer2Identities() {
        final List<HexDigest> ids = new ArrayList<HexDigest>();
        for(Layer2 l: layer2) {
            ids.add(l.identity);
        }
        return ids;
    }
}
