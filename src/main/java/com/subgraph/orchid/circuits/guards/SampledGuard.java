package com.subgraph.orchid.circuits.guards;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.directory.StateFile;

/**
 * A guard in the sampled set of guard-spec (section 4.1), with the state
 * that is saved (sampled_on, listed, confirmed_on and so on) and the state
 * that is not (reachability, last connection attempt, pending).
 *
 * Not thread-safe: EntryGuards uses it under its lock.
 */
class SampledGuard {
    enum Reachable { YES, NO, MAYBE }

    /* Saved */
    private final HexDigest identity;
    private String nickname;
    private Date sampledOn;
    private String sampledBy;
    private boolean listed;
    private Date unlistedSince;
    private Date confirmedOn;
    private int confirmedIndex = -1;
    /* Fields of the state file that this version does not use, kept. */
    private final Map<String, String> otherFields = new LinkedHashMap<String, String>();

    /* Not saved */
    private Reachable reachable = Reachable.MAYBE;
    private Date lastTried;
    private Date failingSince;
    private boolean pending;

    SampledGuard(HexDigest identity, String nickname, Date sampledOn, String sampledBy) {
        this.identity = identity;
        this.nickname = nickname;
        this.sampledOn = sampledOn;
        this.sampledBy = sampledBy;
        this.listed = true;
    }

    /** null if the fields lack rsa_id or sampled_on, or are malformed. */
    static SampledGuard fromFields(Map<String, String> fields) {
        final String in = fields.get("in");
        if(in != null && !in.equals("default")) {
            /* Other guard instances (bridges, restricted) are Tor's, not ours. */
            return null;
        }
        final HexDigest id;
        try {
            id = HexDigest.createFromString(fields.get("rsa_id"));
        } catch (RuntimeException e) {
            return null;
        }
        final Date sampledOn = StateFile.parseDate(fields.get("sampled_on"));
        if(id == null || sampledOn == null) {
            return null;
        }
        final SampledGuard g = new SampledGuard(id, fields.get("nickname"), sampledOn, fields.get("sampled_by"));
        g.listed = !"0".equals(fields.get("listed"));
        g.unlistedSince = g.listed ? null : StateFile.parseDate(fields.get("unlisted_since"));
        g.confirmedOn = StateFile.parseDate(fields.get("confirmed_on"));
        if(g.confirmedOn != null) {
            try {
                g.confirmedIndex = Integer.parseInt(fields.get("confirmed_idx"));
            } catch (RuntimeException e) {
                g.confirmedIndex = Integer.MAX_VALUE;
            }
        }
        for(Map.Entry<String, String> e: fields.entrySet()) {
            if(!isKnownField(e.getKey())) {
                g.otherFields.put(e.getKey(), e.getValue());
            }
        }
        return g;
    }

    private static boolean isKnownField(String key) {
        return key.equals("in") || key.equals("rsa_id") || key.equals("nickname") || key.equals("sampled_on")
                || key.equals("sampled_by") || key.equals("listed") || key.equals("unlisted_since")
                || key.equals("confirmed_on") || key.equals("confirmed_idx");
    }

    Map<String, String> toFields() {
        final Map<String, String> f = new LinkedHashMap<String, String>();
        f.put("in", "default");
        f.put("rsa_id", identity.toString());
        if(nickname != null && !nickname.isEmpty()) {
            f.put("nickname", nickname);
        }
        f.put("sampled_on", StateFile.formatDate(sampledOn));
        if(sampledBy != null && !sampledBy.isEmpty()) {
            f.put("sampled_by", sampledBy.replaceAll("\\s", "_"));
        }
        f.put("listed", listed ? "1" : "0");
        if(!listed && unlistedSince != null) {
            f.put("unlisted_since", StateFile.formatDate(unlistedSince));
        }
        if(confirmedOn != null) {
            f.put("confirmed_on", StateFile.formatDate(confirmedOn));
            f.put("confirmed_idx", Integer.toString(confirmedIndex));
        }
        f.putAll(otherFields);
        return f;
    }

    HexDigest getIdentity() { return identity; }
    String getNickname() { return nickname; }
    void setNickname(String nickname) { this.nickname = nickname; }
    Date getSampledOn() { return sampledOn; }

    boolean isListed() { return listed; }
    Date getUnlistedSince() { return unlistedSince; }
    void setListed(boolean listed, Date unlistedSince) {
        this.listed = listed;
        this.unlistedSince = listed ? null : unlistedSince;
    }

    boolean isConfirmed() { return confirmedOn != null; }
    Date getConfirmedOn() { return confirmedOn; }
    int getConfirmedIndex() { return confirmedIndex; }
    void confirm(Date on, int index) {
        this.confirmedOn = on;
        this.confirmedIndex = index;
    }
    void setConfirmedIndex(int index) { this.confirmedIndex = index; }

    Reachable getReachable() { return reachable; }
    void setReachable(Reachable r) { this.reachable = r; }
    Date getLastTried() { return lastTried; }
    void setLastTried(Date d) { this.lastTried = d; }
    Date getFailingSince() { return failingSince; }
    void setFailingSince(Date d) { this.failingSince = d; }
    boolean isPending() { return pending; }
    void setPending(boolean p) { this.pending = p; }

    @Override
    public String toString() {
        return (nickname == null ? "" : nickname) +"("+ identity +")";
    }
}
