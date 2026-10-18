package com.subgraph.orchid.directory.router;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.data.BandwidthHistory;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.data.exitpolicy.ExitPolicy;
import com.subgraph.orchid.logging.Logger;

public class RouterDescriptorImpl implements RouterDescriptor {
    private static final Logger logger = Logger.getInstance(RouterDescriptorImpl.class);
    private String nickname;
    private IPv4Address address;
    private int routerPort;
    private int directoryPort;

    private int averageBandwidth = -1;
    private int burstBandwidth = -1;
    private int observedBandwidth = -1;

    private String platform;

    private Timestamp published;

    private HexDigest fingerprint;

    private boolean hibernating;

    private int uptime;

    private TorPublicKey onionKey;
    private byte[] ntorOnionKey;
    private byte[] ed25519Identity;
    private TorPublicKey identityKey;
    private ExitPolicy exitPolicy = new ExitPolicy();

    private String contact;
    private Set<String> familyMembers = Collections.emptySet();
    private Set<Integer> linkProtocols = Collections.emptySet();
    private Set<Integer> circuitProtocols = Collections.emptySet();

    private BandwidthHistory readHistory;
    private BandwidthHistory writeHistory;

    private boolean eventDNS = false;
    private boolean cachesExtraInfo = false;
    private boolean hiddenServiceDir = false;
    private HexDigest extraInfoDigest = null;
    private boolean allowSingleHopExits = false;
    private boolean hasValidSignature = false;

    private HexDigest descriptorDigest;
    private String rawDocumentData;

    private long lastListed;
    private CacheLocation cacheLocation = CacheLocation.NOT_CACHED;

    public void setNickname(String nickname) { this.nickname = nickname; }
    public void setAddress(IPv4Address address) { this.address = address; }
    public void setRouterPort(int port) { this.routerPort = port; }
    void setDirectoryPort(int port) { this.directoryPort = port; }
    void setPlatform(String platform) { this.platform = platform; }
    void setPublished(Timestamp published) { this.published = published; }
    void setFingerprint(HexDigest fingerprint) { this.fingerprint = fingerprint; }
    void setHibernating(boolean flag) { this.hibernating = flag; }
    void setUptime(int uptime) { this.uptime = uptime; }
    public void setOnionKey(TorPublicKey key) { this.onionKey = key; }
    void setNtorOnionKey(byte[] key) { this.ntorOnionKey = key; }
    void setEd25519Identity(byte[] key) { this.ed25519Identity = key; }
    void setIdentityKey(TorPublicKey key) { this.identityKey = key; }
    void setContact(String contact) { this.contact = contact; }
    void setEventDNS() { eventDNS = true; }
    void setHiddenServiceDir() { hiddenServiceDir = true; }
    void setExtraInfoDigest(HexDigest digest) { this.extraInfoDigest = digest; }
    void setCachesExtraInfo() { cachesExtraInfo = true; }
    void setAllowSingleHopExits() { allowSingleHopExits = true; }
    void setReadHistory(BandwidthHistory history) { this.readHistory= history; }
    void setWriteHistory(BandwidthHistory history) { this.writeHistory = history; }
    void setValidSignature() { hasValidSignature = true; }
    void setDescriptorHash(HexDigest digest) { descriptorDigest = digest; }
    void setRawDocumentData(String rawData) { rawDocumentData = rawData; }

    void addAcceptRule(String rule) {
        exitPolicy.addAcceptRule(rule);
    }

    void addRejectRule(String rule) {
        exitPolicy.addRejectRule(rule);
    }

    void setBandwidthValues(int average, int burst, int observed) {
        this.averageBandwidth = average;
        this.burstBandwidth = burst;
        this.observedBandwidth = observed;
    }

    void addFamilyMember(String familyMember) {
        if(familyMembers.isEmpty()) {
            familyMembers = new HashSet<String>();
        }
        familyMembers.add(familyMember);
    }

    void addCircuitProtocolVersion(int version) {
        if(circuitProtocols.isEmpty()){
            circuitProtocols = new HashSet<Integer>();
        }
        circuitProtocols.add(version);
    }

    void addLinkProtocolVersion(int version) {
        if(linkProtocols.isEmpty()){
            linkProtocols = new HashSet<Integer>();
        }
        linkProtocols.add(version);	
    }

    @Override
    public boolean isValidDocument() {
        // verify required fields exist, see dirspec.txt section 2.1
        return hasValidSignature && (nickname != null) && (address != null) &&
                (averageBandwidth != -1) && (routerPort != 0 || directoryPort != 0) &&
                (published != null) && (onionKey != null || ntorOnionKey != null) && (identityKey != null) &&
                (descriptorDigest != null);
    }

    @Override
    public String getNickname() {
        return nickname;
    }

    @Override
    public IPv4Address getAddress() {
        return address;
    }

    @Override
    public int getRouterPort() {
        return routerPort;
    }

    @Override
    public int getDirectoryPort() {
        return directoryPort;
    }

    @Override
    public int getAverageBandwidth() {
        return averageBandwidth;
    }

    @Override
    public int getBurstBandwidth() {
        return burstBandwidth;
    }

    @Override
    public int getObservedBandwidth() {
        return observedBandwidth;
    }

    @Override
    public String getPlatform() {
        return platform;
    }

    @Override
    public HexDigest getFingerprint() {
        return fingerprint;
    }

    @Override
    public int getUptime() {
        return uptime;
    }

    @Override
    public TorPublicKey getOnionKey() {
        return onionKey;
    }

    @Override
    public byte[] getNTorOnionKey() {
        return ntorOnionKey;
    }

    public byte[] getEd25519Identity() {
        return ed25519Identity;
    }

    @Override
    public TorPublicKey getIdentityKey() {
        return identityKey;
    }

    @Override
    public String getContact() {
        return contact;
    }

    @Override
    public boolean isHibernating() {
        return hibernating;
    }

    @Override
    public boolean cachesExtraInfo() {
        return cachesExtraInfo;
    }

    @Override
    public boolean allowsSingleHopExits() {
        return allowSingleHopExits;
    }

    @Override
    public Timestamp getPublishedTime() {
        return published;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Router Descriptor: (name: ");
        builder.append(nickname);
        builder.append(" orport=");
        builder.append(routerPort);
        builder.append(" dirport=");
        builder.append(directoryPort);
        builder.append(" address=");
        builder.append(address);
        builder.append(" platform=");
        builder.append(platform);
        builder.append(" published=");
        builder.append(published.getDate());
        builder.append(")");
        return builder.toString();
    }

    public void print() {
        logger.debug("nickname: "+ nickname +" IP: "+ address +" port: "+ routerPort);
        logger.debug("directory port: "+ directoryPort +" platform: "+ platform);
        logger.debug("Bandwidth(avg/burst/observed): "+ averageBandwidth +"/"+ burstBandwidth +"/"+ observedBandwidth);
        logger.debug("Publication time: "+ published +" Uptime: "+ uptime);
        if(fingerprint != null){
            logger.debug("Fingerprint: "+ fingerprint);
        }
        if(contact != null){
            logger.debug("Contact: "+ contact);
        }
    }
    @Override
    public boolean exitPolicyAccepts(IPv4Address address, int port) {
        return exitPolicy.acceptsDestination(address, port);
    }

    @Override
    public boolean exitPolicyAccepts(int port) {
        return exitPolicy.acceptsPort(port);
    }

    @Override
    public HexDigest getExtraInfoDigest() {
        return extraInfoDigest;
    }

    @Override
    public boolean isHiddenServiceDirectory() {
        return hiddenServiceDir;
    }

    @Override
    public Set<String> getFamilyMembers() {
        return familyMembers;
    }

    @Override
    public boolean supportsEventDNS() {
        return eventDNS;
    }

    public BandwidthHistory getReadHistory() {
        return readHistory;
    }

    public BandwidthHistory getWriteHistory() {
        return writeHistory;
    }

    @Override
    public boolean isNewerThan(RouterDescriptor other) {
        return other.getPublishedTime().isBefore(published);
    }

    @Override
    public HexDigest getDescriptorDigest() {
        return descriptorDigest;
    }

    @Override
    public String getRawDocumentData() {
        return rawDocumentData;
    }

    @Override
    public ByteBuffer getRawDocumentBytes() {
        if(getRawDocumentData() == null) {
            return ByteBuffer.allocate(0);
        } else {
            return ByteBuffer.wrap(getRawDocumentData().getBytes(Tor.getDefaultCharset()));
        }
    }

    @Override
    public boolean equals(Object o) {
        if(!(o instanceof RouterDescriptorImpl)) {
            return false;
        }
        final RouterDescriptorImpl other = (RouterDescriptorImpl) o;
        if(other.getDescriptorDigest() == null || descriptorDigest == null){
            return false;
        }

        return other.getDescriptorDigest().equals(descriptorDigest);
    }

    @Override
    public int hashCode() {
        if(descriptorDigest == null){
            return 0;
        }
        return descriptorDigest.hashCode();
    }

    @Override
    public ExitPolicy getExitPolicy() {
        return exitPolicy;
    }

    @Override
    public void setLastListed(long timestamp) {
        this.lastListed = timestamp;
    }

    @Override
    public long getLastListed() {
        return lastListed;
    }
    @Override
    public void setCacheLocation(CacheLocation location) {
        this.cacheLocation = location;
    }
    @Override
    public CacheLocation getCacheLocation() {
        return cacheLocation;
    }

    @Override
    public int getBodyLength() {
        return rawDocumentData.length();
    }
}
