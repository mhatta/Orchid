package com.subgraph.orchid;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What the SOCKS and HTTP tunnel ports of a client have been asked since
 * it started, in total and by password profile
 * ({@link TorConfig#setSocksPasswords(Map)}): see
 * {@link TorClient#getProxyStatistics()}.  A snapshot: it does not change.
 *
 * <p>The number to watch is {@link Counts#getAddressOnlyRequests()}: the
 * requests that gave an IP address instead of a host name.  An application
 * that sends them has most likely looked the name up itself, through the
 * device's DNS resolver and outside Tor, so that its network (and the DNS
 * server) saw which hosts it went to.  With profiles, the profile says
 * which application it is.
 *
 * @since 2.9.0
 */
public final class ProxyStatistics {

    /** The profile of requests that gave no password of a profile. */
    public static final String NO_PROFILE = "";

    /** The counts of one profile, or of all of them. */
    public static final class Counts {
        private final long requests;
        private final long addressOnlyRequests;
        private final long refusedUnsafeRequests;

        public Counts(long requests, long addressOnlyRequests, long refusedUnsafeRequests) {
            this.requests = requests;
            this.addressOnlyRequests = addressOnlyRequests;
            this.refusedUnsafeRequests = refusedUnsafeRequests;
        }

        /** The CONNECT requests read (after authentication), served or not. */
        public long getRequests() {
            return requests;
        }

        /**
         * The requests that gave an IP address, not a host name: SOCKS 4
         * (not 4a), SOCKS 5 with an IPv4 or IPv6 address, or a host name
         * or CONNECT authority that is an address literal.
         */
        public long getAddressOnlyRequests() {
            return addressOnlyRequests;
        }

        /** The address-only requests refused because of {@link TorConfig#getSafeSocks()}. */
        public long getRefusedUnsafeRequests() {
            return refusedUnsafeRequests;
        }

        Counts plus(Counts o) {
            return new Counts(requests + o.requests, addressOnlyRequests + o.addressOnlyRequests,
                    refusedUnsafeRequests + o.refusedUnsafeRequests);
        }

        @Override
        public String toString() {
            return requests + " requests, "+ addressOnlyRequests +" with an address only, "+
                    refusedUnsafeRequests +" refused";
        }
    }

    private static final Counts ZERO = new Counts(0, 0, 0);
    private static final ProxyStatistics EMPTY = new ProxyStatistics(Collections.<String, Counts>emptyMap());

    private final Map<String, Counts> byProfile;
    private final Counts total;

    public ProxyStatistics(Map<String, Counts> byProfile) {
        this.byProfile = Collections.unmodifiableMap(new LinkedHashMap<String, Counts>(byProfile));
        Counts t = ZERO;
        for(Counts c: byProfile.values()) {
            t = t.plus(c);
        }
        this.total = t;
    }

    /** No requests. */
    public static ProxyStatistics empty() {
        return EMPTY;
    }

    public Counts getTotal() {
        return total;
    }

    /**
     * The counts by profile name, {@link #NO_PROFILE} for requests without a
     * profile's password (no password, or {@link TorConfig#getSocksPassword()}).
     * Only profiles with requests are in the map.
     */
    public Map<String, Counts> getByProfile() {
        return byProfile;
    }

    /** The counts of one profile; zero if it had no requests. */
    public Counts get(String profile) {
        final Counts c = byProfile.get(profile);
        return c == null ? ZERO : c;
    }

    @Override
    public String toString() {
        return "ProxyStatistics["+ total + ", by profile "+ byProfile + "]";
    }
}
