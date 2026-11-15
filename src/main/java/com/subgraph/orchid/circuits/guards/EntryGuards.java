package com.subgraph.orchid.circuits.guards;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryDownloader;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser;
import com.subgraph.orchid.circuits.path.CircuitNodeChooser.WeightRule;
import com.subgraph.orchid.circuits.path.RouterFilter;
import com.subgraph.orchid.circuits.path.TorConfigNodeFilter;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.logging.Logger;

/**
 * Entry guard selection as in Tor's guard-spec (proposal 271), for the
 * client's default guard set.
 *
 * <ul>
 * <li>A persistent, ordered <em>sample</em> of guards is drawn from the
 * consensus, weighted by guard bandwidth, and grows only when fewer than
 * {@value #DEFAULT_MIN_FILTERED_SAMPLE} of its guards are usable.</li>
 * <li>Guards through which a circuit was built for use become
 * <em>confirmed</em>, in the order this happened.</li>
 * <li>The first {@value #DEFAULT_N_PRIMARY_GUARDS} usable guards, confirmed
 * ones first, are the <em>primary</em> guards.  Circuits go through the
 * first primary guard that is not known to be down; one-hop directory
 * requests through one of the first three.</li>
 * <li>Only when every primary guard is down does a circuit go through
 * another guard, one at a time, confirmed guards first.</li>
 * <li>Guards are sampled whether or not their descriptor has arrived, and
 * a circuit waits for the descriptor of its primary guard (guard-spec
 * 4.12), so that the directory servers cannot choose a client's guards by
 * the descriptors they serve.</li>
 * <li>Reachability is learnt from circuits: a failed connection marks a
 * guard down, and it is tried again on the guard-spec retry schedules.
 * Guards are not probed.</li>
 * </ul>
 *
 * Not implemented: the "waiting for better guard" state of guard-spec 4.9
 * (a circuit through a non-primary guard is used at once instead of
 * waiting to see whether a primary guard comes back), path bias, and the
 * separate guard instances for bridges and restrictive configurations.
 * With UseBridges the bridges are chosen by {@link Bridges} as before.
 *
 * The defaults are those of guard-spec; the consensus parameters of the
 * same names override them.
 */
public class EntryGuards {
    private static final Logger logger = Logger.getInstance(EntryGuards.class);

    static final int DEFAULT_MIN_FILTERED_SAMPLE = 20;
    static final int DEFAULT_MAX_SAMPLE_THRESHOLD_PERCENT = 20;
    static final int DEFAULT_MAX_SAMPLE_SIZE = 60;
    static final int DEFAULT_GUARD_LIFETIME_DAYS = 120;
    static final int DEFAULT_REMOVE_UNLISTED_AFTER_DAYS = 20;
    static final int DEFAULT_N_PRIMARY_GUARDS = 3;
    static final int DEFAULT_N_PRIMARY_GUARDS_TO_USE = 1;
    static final int DEFAULT_N_PRIMARY_DIR_GUARDS_TO_USE = 3;
    static final int DEFAULT_CONFIRMED_MIN_LIFETIME_DAYS = 60;
    static final int DEFAULT_INTERNET_LIKELY_DOWN_SECONDS = 600;

    private static final long MINUTE = TimeUnit.MINUTES.toMillis(1);
    private static final long HOUR = TimeUnit.HOURS.toMillis(1);
    private static final long DAY = TimeUnit.DAYS.toMillis(1);

    /** Time, so that tests can move it. */
    interface Clock {
        long now();
    }

    private static final Clock SYSTEM_CLOCK = new Clock() {
        public long now() {
            return System.currentTimeMillis();
        }
    };

    private final TorConfig config;
    private final Directory directory;
    private final CircuitNodeChooser nodeChooser;
    private final TorConfigNodeFilter configFilter;
    private final Bridges bridges;
    private final TorRandom random;
    private final Clock clock;
    private final Object lock = new Object();

    /* In sample order.  Guarded by lock. */
    private final List<SampledGuard> sampled = new ArrayList<SampledGuard>();
    private List<SampledGuard> primary = new ArrayList<SampledGuard>();
    private boolean loaded = false;
    private long lastTimeOnInternet = Long.MIN_VALUE;

    public EntryGuards(TorConfig config, DirectoryDownloader directoryDownloader, Directory directory) {
        this(config, directory, new CircuitNodeChooser(config, directory), new Bridges(config, directoryDownloader), SYSTEM_CLOCK);
    }

    EntryGuards(TorConfig config, Directory directory, CircuitNodeChooser nodeChooser, Bridges bridges, Clock clock) {
        this.config = config;
        this.directory = directory;
        this.nodeChooser = nodeChooser;
        this.configFilter = new TorConfigNodeFilter(config);
        this.bridges = bridges;
        this.random = new TorRandom();
        this.clock = clock;
    }

    public boolean isUsingBridges() {
        return config.getUseBridges();
    }

    /**
     * The guard for the first hop of a circuit, or null if none can be
     * chosen yet (no consensus, the descriptor of a primary guard has not
     * arrived, or no guard is compatible with excluded).
     * Routers in excluded (the other hops and their relatives) are not
     * chosen.  With UseBridges, a bridge.
     */
    public Router chooseRandomGuard(Set<Router> excluded) throws InterruptedException {
        if(config.getUseBridges()) {
            return bridges.chooseRandomBridge(excluded);
        }
        return chooseGuard(excluded, false);
    }

    /**
     * A guard for a one-hop directory request (directory guards, proposal
     * 207), or null if there is none yet, e.g. before the first consensus.
     */
    public Router chooseDirectoryGuard() throws InterruptedException {
        if(config.getUseBridges()) {
            return bridges.chooseRandomBridge(Collections.<Router>emptySet());
        }
        return chooseGuard(Collections.<Router>emptySet(), true);
    }

    /**
     * The network changed (another Wi-Fi network, mobile data, back
     * online): the primary guards are worth trying again at once, before
     * any other guard is used.
     */
    public void networkChanged() {
        synchronized (lock) {
            markPrimaryGuardsMaybe();
        }
    }

    /** A connection to router, chosen as a guard, could not be made. */
    public void guardConnectionFailed(Router router) {
        synchronized (lock) {
            final SampledGuard g = find(router);
            if(g == null) {
                return;
            }
            final long now = clock.now();
            g.setReachable(SampledGuard.Reachable.NO);
            if(g.getFailingSince() == null) {
                g.setFailingSince(new Date(now));
            }
            /* The retry schedule counts from this failure. */
            g.setLastTried(new Date(now));
            g.setPending(false);
            logger.debug("Guard "+ g +" is unreachable");
        }
    }

    /** The first hop of a circuit through router, chosen as a guard, was created. */
    public void guardReachable(Router router) {
        synchronized (lock) {
            final SampledGuard g = find(router);
            if(g != null) {
                markReachable(g);
            }
        }
    }

    /**
     * A circuit for user traffic was built through router, chosen as a
     * guard: it becomes a confirmed guard if it was not one.
     */
    public void guardUsed(Router router) {
        synchronized (lock) {
            final SampledGuard g = find(router);
            if(g == null) {
                return;
            }
            markReachable(g);
            if(!g.isConfirmed()) {
                final long now = clock.now();
                g.confirm(new Date(randomPast(now, lifetime() / 10)), nextConfirmedIndex());
                logger.debug("Guard "+ g +" is now confirmed");
                recomputePrimary();
                save();
            }
        }
    }

    /* All methods below are called holding lock. */

    private Router chooseGuard(Set<Router> excluded, boolean forDirectory) {
        synchronized (lock) {
            refresh();
            if(!hasFilteredGuard()) {
                /* No consensus yet, or no sampled guard in it: nothing to choose from. */
                return null;
            }
            for(int attempt = 0; attempt < 2; attempt++) {
                final List<Router> primaries = usablePrimaryGuards(excluded, forDirectory);
                if(!primaries.isEmpty()) {
                    /*
                     * guard-spec 4.12: a circuit needs the guard's
                     * descriptor.  While a primary guard that would be
                     * used has none yet, the circuit waits for it rather
                     * than go through another guard: otherwise a directory
                     * server could steer the client away from its primary
                     * guards by withholding their descriptors.
                     */
                    if(!forDirectory && lacksDescriptor(primaries)) {
                        logger.debug("Waiting for the descriptors of the primary guards");
                        return null;
                    }
                    return chooseAmong(primaries);
                }
                final Router other = chooseNonPrimary(excluded, forDirectory);
                if(other != null) {
                    return other;
                }
                /*
                 * guard-spec 4.6: every sampled guard is down.  Mark them all
                 * as worth trying, so that circuits keep being attempted.
                 */
                if(attempt == 0) {
                    logger.info("All sampled guards seem down; trying them again");
                    for(SampledGuard g: sampled) {
                        g.setReachable(SampledGuard.Reachable.MAYBE);
                    }
                }
            }
            return null;
        }
    }

    private boolean hasFilteredGuard() {
        for(SampledGuard g: sampled) {
            if(isFiltered(g)) {
                return true;
            }
        }
        return false;
    }

    /*
     * The primary guards a request may go through now: the first n that
     * are not known to be down and not excluded, where n is 1 for circuits
     * and 3 for directory requests.
     */
    private List<Router> usablePrimaryGuards(Set<Router> excluded, boolean forDirectory) {
        final int n = forDirectory ? primaryDirGuardsToUse() : primaryGuardsToUse();
        final List<Router> routers = new ArrayList<Router>();
        for(SampledGuard g: primary) {
            if(g.getReachable() == SampledGuard.Reachable.NO) {
                continue;
            }
            final Router r = directory.getRouterByIdentity(g.getIdentity());
            if(r != null && !excluded.contains(r) && routers.size() < n) {
                routers.add(r);
            }
        }
        return routers;
    }

    private static boolean lacksDescriptor(List<Router> routers) {
        for(Router r: routers) {
            if(r.getCurrentDescriptor() == null) {
                return true;
            }
        }
        return false;
    }

    private Router chooseAmong(List<Router> routers) {
        final Router chosen = routers.get(random.nextInt(routers.size()));
        find(chosen).setLastTried(new Date(clock.now()));
        return chosen;
    }

    /*
     * guard-spec 4.6: confirmed guards first, in confirmed order; then the
     * rest of the usable sample in sample order.  A guard already being
     * tried (pending) is skipped if another is available.
     */
    private Router chooseNonPrimary(Set<Router> excluded, boolean forDirectory) {
        final List<SampledGuard> confirmed = new ArrayList<SampledGuard>();
        final List<SampledGuard> others = new ArrayList<SampledGuard>();
        for(SampledGuard g: sampled) {
            if(primary.contains(g) || g.getReachable() == SampledGuard.Reachable.NO || !isFiltered(g)) {
                continue;
            }
            (g.isConfirmed() ? confirmed : others).add(g);
        }
        sortByConfirmedIndex(confirmed);
        for(List<SampledGuard> list: Arrays.<List<SampledGuard>>asList(confirmed, others)) {
            SampledGuard first = null;
            for(SampledGuard g: list) {
                final Router r = directory.getRouterByIdentity(g.getIdentity());
                if(!isUsableFor(r, excluded, forDirectory)) {
                    continue;
                }
                if(!g.isPending()) {
                    return useNonPrimary(g, r);
                }
                if(first == null) {
                    first = g;
                }
            }
            if(first != null) {
                return useNonPrimary(first, directory.getRouterByIdentity(first.getIdentity()));
            }
        }
        return null;
    }

    private Router useNonPrimary(SampledGuard g, Router r) {
        g.setPending(true);
        g.setLastTried(new Date(clock.now()));
        logger.debug("Primary guards unusable; trying guard "+ g);
        return r;
    }

    private boolean isUsableFor(Router r, Set<Router> excluded, boolean forDirectory) {
        if(r == null || excluded.contains(r)) {
            return false;
        }
        /* guard-spec 4.12: a circuit through a guard needs its descriptor. */
        return forDirectory || r.getCurrentDescriptor() != null;
    }

    private void markReachable(SampledGuard g) {
        final long now = clock.now();
        final boolean wasPrimary = primary.contains(g);
        g.setReachable(SampledGuard.Reachable.YES);
        g.setFailingSince(null);
        g.setPending(false);
        /*
         * guard-spec 4.8: if a non-primary guard works after the network
         * seems to have been down, the primary guards may work again too.
         */
        if(!wasPrimary && (lastTimeOnInternet == Long.MIN_VALUE || now - lastTimeOnInternet > internetLikelyDownMillis())) {
            markPrimaryGuardsMaybe();
        }
        lastTimeOnInternet = now;
    }

    private void markPrimaryGuardsMaybe() {
        for(SampledGuard g: primary) {
            g.setReachable(SampledGuard.Reachable.MAYBE);
        }
    }

    /*
     * Bring the sample up to date with the consensus, retry guards whose
     * retry time has come, grow the sample if needed and recompute the
     * primary guards; save if anything that is saved changed.
     */
    void refresh() {
        loadIfNeeded();
        final long now = clock.now();
        boolean changed = false;
        final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
        if(consensus != null) {
            changed |= updateListed(now);
            if(consensus.isLive()) {
                changed |= removeExpired(now);
            }
        }
        retryUnreachable(now);
        if(consensus != null) {
            changed |= extendSample(now);
        }
        recomputePrimary();
        if(changed) {
            save();
        }
    }

    private void loadIfNeeded() {
        if(loaded) {
            return;
        }
        loaded = true;
        final List<Map<String, String>> state = directory.getGuardState();
        for(Map<String, String> fields: state) {
            final SampledGuard g = SampledGuard.fromFields(fields);
            if(g != null && find(g.getIdentity()) == null) {
                sampled.add(g);
            }
        }
        renumberConfirmed();
        logger.debug("Loaded "+ sampled.size() +" sampled guards");
    }

    private boolean updateListed(long now) {
        boolean changed = false;
        for(SampledGuard g: sampled) {
            final Router r = directory.getRouterByIdentity(g.getIdentity());
            final boolean listed = isGuardInConsensus(r);
            if(listed != g.isListed()) {
                g.setListed(listed, new Date(randomPast(now, removeUnlistedAfter() / 5)));
                changed = true;
            }
            if(r != null && r.getNickname() != null && !r.getNickname().equals(g.getNickname())) {
                g.setNickname(r.getNickname());
                changed = true;
            }
        }
        return changed;
    }

    /* guard-spec 4.1: drop guards long unlisted, or sampled long ago and not recently confirmed. */
    private boolean removeExpired(long now) {
        boolean changed = false;
        for(Iterator<SampledGuard> it = sampled.iterator(); it.hasNext(); ) {
            final SampledGuard g = it.next();
            final boolean unlistedTooLong = !g.isListed() && g.getUnlistedSince() != null
                    && now - g.getUnlistedSince().getTime() > removeUnlistedAfter();
            final boolean tooOld = now - g.getSampledOn().getTime() > lifetime()
                    && (!g.isConfirmed() || now - g.getConfirmedOn().getTime() > confirmedMinLifetime());
            if(unlistedTooLong || tooOld) {
                logger.debug("Removing guard "+ g +" from the sample");
                it.remove();
                primary.remove(g);
                changed = true;
            }
        }
        if(changed) {
            renumberConfirmed();
        }
        return changed;
    }

    /* guard-spec 4.5 and appendix A.1: the retry schedules. */
    private void retryUnreachable(long now) {
        for(SampledGuard g: sampled) {
            if(g.getReachable() != SampledGuard.Reachable.NO) {
                continue;
            }
            final long failingFor = (g.getFailingSince() == null) ? 0 : now - g.getFailingSince().getTime();
            final long interval = primary.contains(g) ? primaryRetryInterval(failingFor) : retryInterval(failingFor);
            if(g.getLastTried() == null || now - g.getLastTried().getTime() >= interval) {
                g.setReachable(SampledGuard.Reachable.MAYBE);
            }
        }
    }

    static long primaryRetryInterval(long failingFor) {
        if(failingFor < 6 * HOUR) {
            return 10 * MINUTE;
        } else if(failingFor < 96 * HOUR) {
            return 90 * MINUTE;
        } else if(failingFor < 7 * DAY) {
            return 4 * HOUR;
        } else {
            return 9 * HOUR;
        }
    }

    static long retryInterval(long failingFor) {
        if(failingFor < 6 * HOUR) {
            return HOUR;
        } else if(failingFor < 96 * HOUR) {
            return 4 * HOUR;
        } else if(failingFor < 7 * DAY) {
            return 18 * HOUR;
        } else {
            return 36 * HOUR;
        }
    }

    /*
     * guard-spec 4.2: while fewer than MIN_FILTERED_SAMPLE sampled guards
     * are usable, sample more, weighted by guard bandwidth, up to the
     * maximum sample size.
     */
    private boolean extendSample(long now) {
        int usable = 0;
        for(SampledGuard g: sampled) {
            if(isFiltered(g) && g.getReachable() != SampledGuard.Reachable.NO) {
                usable++;
            }
        }
        final int minFiltered = param("guard-min-filtered-sample-size", DEFAULT_MIN_FILTERED_SAMPLE, 1, 1000);
        if(usable >= minFiltered) {
            return false;
        }
        final int maxSample = maxSampleSize(minFiltered);
        boolean changed = false;
        /*
         * Unlike guard-spec 4.2, only guards that EntryNodes and
         * ExcludeNodes allow are sampled: with a small EntryNodes set the
         * sample would otherwise fill up with guards that can never be
         * used.  Tor uses a separate "restricted" sample for that case.
         */
        /*
         * The sample is drawn from the consensus, whether or not a guard's
         * descriptor has been downloaded.  If only guards with a descriptor
         * could be sampled, the directory server that answers first after
         * the first start, when few descriptors have arrived, could decide
         * which guards the client samples by the descriptors it serves.
         */
        while(usable < minFiltered && sampled.size() < maxSample) {
            final Router r = nodeChooser.chooseRandomNode(WeightRule.WEIGHT_FOR_GUARD, new RouterFilter() {
                public boolean filter(Router router) {
                    return isGuardInConsensus(router) && configFilter.isAllowedAsGuard(router) && find(router) == null;
                }
            }, false);
            if(r == null) {
                break;
            }
            final SampledGuard g = new SampledGuard(r.getIdentityHash(), r.getNickname(),
                    new Date(randomPast(now, lifetime() / 10)), Tor.getImplementation() +"-"+ Tor.getVersion());
            sampled.add(g);
            changed = true;
            logger.debug("Added guard "+ g +" to the sample");
            if(isFiltered(g)) {
                usable++;
            }
        }
        return changed;
    }

    private int maxSampleSize(int minFiltered) {
        int guards = 0;
        for(Router r: directory.getAllRouters()) {
            if(isGuardInConsensus(r)) {
                guards++;
            }
        }
        final int percent = param("guard-max-sample-threshold-percent", DEFAULT_MAX_SAMPLE_THRESHOLD_PERCENT, 1, 100);
        final int size = param("guard-max-sample-size", DEFAULT_MAX_SAMPLE_SIZE, 1, 1000);
        return Math.max(minFiltered, Math.min(size, guards * percent / 100));
    }

    /*
     * guard-spec 4.4: confirmed usable guards first, in confirmed order;
     * then the guards that were already primary; then the rest in sample
     * order.
     */
    void recomputePrimary() {
        final int n = param("guard-n-primary-guards", DEFAULT_N_PRIMARY_GUARDS, 1, 100);
        final List<SampledGuard> confirmed = new ArrayList<SampledGuard>();
        for(SampledGuard g: sampled) {
            if(g.isConfirmed() && isFiltered(g)) {
                confirmed.add(g);
            }
        }
        sortByConfirmedIndex(confirmed);
        final List<SampledGuard> next = new ArrayList<SampledGuard>();
        for(SampledGuard g: confirmed) {
            if(next.size() < n) {
                next.add(g);
            }
        }
        for(SampledGuard g: primary) {
            if(next.size() < n && !next.contains(g) && sampled.contains(g) && isFiltered(g)) {
                next.add(g);
            }
        }
        for(SampledGuard g: sampled) {
            if(next.size() < n && !next.contains(g) && !g.isConfirmed() && isFiltered(g)) {
                next.add(g);
            }
        }
        if(!next.equals(primary)) {
            logger.debug("Primary guards: "+ next);
        }
        primary = next;
    }

    /* FILTERED_GUARDS: listed, in the consensus as a guard, and allowed by the configuration. */
    private boolean isFiltered(SampledGuard g) {
        if(!g.isListed()) {
            return false;
        }
        final Router r = directory.getRouterByIdentity(g.getIdentity());
        return isGuardInConsensus(r) && configFilter.isAllowedAsGuard(r);
    }

    /* guard-spec 4.0: GUARDS has the flags Valid, Running, Guard, Stable, Fast and V2Dir. */
    static boolean isGuardInConsensus(Router r) {
        return r != null && r.isValid() && r.isRunning() && r.isPossibleGuard() && r.isStable() && r.isFast()
                && r.isDirectoryCache();
    }

    private SampledGuard find(Router router) {
        return (router == null) ? null : find(router.getIdentityHash());
    }

    private SampledGuard find(HexDigest identity) {
        for(SampledGuard g: sampled) {
            if(g.getIdentity().equals(identity)) {
                return g;
            }
        }
        return null;
    }

    private int nextConfirmedIndex() {
        int max = -1;
        for(SampledGuard g: sampled) {
            if(g.isConfirmed()) {
                max = Math.max(max, g.getConfirmedIndex());
            }
        }
        return max + 1;
    }

    private void renumberConfirmed() {
        final List<SampledGuard> confirmed = new ArrayList<SampledGuard>();
        for(SampledGuard g: sampled) {
            if(g.isConfirmed()) {
                confirmed.add(g);
            }
        }
        sortByConfirmedIndex(confirmed);
        for(int i = 0; i < confirmed.size(); i++) {
            confirmed.get(i).setConfirmedIndex(i);
        }
    }

    private static void sortByConfirmedIndex(List<SampledGuard> guards) {
        Collections.sort(guards, new Comparator<SampledGuard>() {
            public int compare(SampledGuard a, SampledGuard b) {
                return Integer.compare(a.getConfirmedIndex(), b.getConfirmedIndex());
            }
        });
    }

    private void save() {
        final List<Map<String, String>> state = new ArrayList<Map<String, String>>();
        for(SampledGuard g: sampled) {
            state.add(g.toFields());
        }
        directory.setGuardState(state);
    }

    /* RAND(now, interval) of guard-spec: a time up to interval before now. */
    private long randomPast(long now, long interval) {
        if(interval <= 0) {
            return now;
        }
        return now - random.nextLong(interval);
    }

    private int param(String name, int defaultValue, int min, int max) {
        final ConsensusDocument consensus = directory.getCurrentConsensusDocument();
        return (consensus == null) ? defaultValue : consensus.getIntegerParameter(name, defaultValue, min, max);
    }

    private long lifetime() {
        return param("guard-lifetime-days", DEFAULT_GUARD_LIFETIME_DAYS, 1, 3650) * DAY;
    }

    private long removeUnlistedAfter() {
        return param("guard-remove-unlisted-guards-after-days", DEFAULT_REMOVE_UNLISTED_AFTER_DAYS, 1, 365) * DAY;
    }

    private long confirmedMinLifetime() {
        return param("guard-confirmed-min-lifetime-days", DEFAULT_CONFIRMED_MIN_LIFETIME_DAYS, 1, 3650) * DAY;
    }

    private long internetLikelyDownMillis() {
        return param("guard-internet-likely-down-interval", DEFAULT_INTERNET_LIKELY_DOWN_SECONDS, 1, 86400) * 1000L;
    }

    private int primaryGuardsToUse() {
        return param("guard-n-primary-guards-to-use", DEFAULT_N_PRIMARY_GUARDS_TO_USE, 1, 100);
    }

    private int primaryDirGuardsToUse() {
        return param("guard-n-primary-dir-guards-to-use", DEFAULT_N_PRIMARY_DIR_GUARDS_TO_USE, 1, 100);
    }

    /* For tests */

    List<SampledGuard> getSampledGuards() {
        synchronized (lock) {
            return new ArrayList<SampledGuard>(sampled);
        }
    }

    List<SampledGuard> getPrimaryGuards() {
        synchronized (lock) {
            return new ArrayList<SampledGuard>(primary);
        }
    }
}
