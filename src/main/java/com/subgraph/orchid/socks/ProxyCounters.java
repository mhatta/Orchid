package com.subgraph.orchid.socks;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.subgraph.orchid.ProxyStatistics;

/** The counts behind {@link ProxyStatistics}, shared by the ports of one listener. */
final class ProxyCounters {
    private static final class Entry {
        final AtomicLong requests = new AtomicLong();
        final AtomicLong addressOnly = new AtomicLong();
        final AtomicLong refused = new AtomicLong();
    }

    /*
     * At most this many profiles are counted, so that the map cannot grow
     * without bound if profiles are replaced again and again; the requests
     * of further profiles are counted without a profile.
     */
    static final int MAX_PROFILES = 256;

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<String, Entry>();

    void record(String profile, boolean addressOnly, boolean refused) {
        Entry e = entries.get(profile == null ? ProxyStatistics.NO_PROFILE : profile);
        if(e == null) {
            final String key = (entries.size() < MAX_PROFILES && profile != null) ? profile : ProxyStatistics.NO_PROFILE;
            final Entry fresh = new Entry();
            final Entry old = entries.putIfAbsent(key, fresh);
            e = (old == null) ? fresh : old;
        }
        e.requests.incrementAndGet();
        if(addressOnly) {
            e.addressOnly.incrementAndGet();
        }
        if(refused) {
            e.refused.incrementAndGet();
        }
    }

    ProxyStatistics snapshot() {
        final Map<String, ProxyStatistics.Counts> m = new TreeMap<String, ProxyStatistics.Counts>();
        for(Map.Entry<String, Entry> e: entries.entrySet()) {
            final Entry v = e.getValue();
            m.put(e.getKey(), new ProxyStatistics.Counts(v.requests.get(), v.addressOnly.get(), v.refused.get()));
        }
        return new ProxyStatistics(m);
    }
}
