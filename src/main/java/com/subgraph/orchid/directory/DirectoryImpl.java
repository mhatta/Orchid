package com.subgraph.orchid.directory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.ConsensusDocument.ConsensusFlavor;
import com.subgraph.orchid.ConsensusDocument.RequiredCertificate;
import com.subgraph.orchid.Descriptor;
import com.subgraph.orchid.Directory;
import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.DirectoryStore;
import com.subgraph.orchid.DirectoryStore.CacheFile;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.AutoBoolValue;
import com.subgraph.orchid.TorException;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.RandomSet;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParserFactory;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.events.Event;
import com.subgraph.orchid.events.EventHandler;
import com.subgraph.orchid.events.EventManager;
import com.subgraph.orchid.logging.Logger;

public class DirectoryImpl implements Directory {
    private static final Logger logger = Logger.getInstance(DirectoryImpl.class);

    private final Object loadLock = new Object();
    private boolean isLoaded = false;

    private final DirectoryStore store;
    private final TorConfig config;
    private final StateFile stateFile;
    private final DescriptorCache<RouterMicrodescriptor> microdescriptorCache;
    private final DescriptorCache<RouterDescriptor> basicDescriptorCache;

    private final Map<HexDigest, RouterImpl> routersByIdentity;
    private final Map<String, RouterImpl> routersByNickname;
    private final RandomSet<RouterImpl> directoryCaches;
    private final Set<ConsensusDocument.RequiredCertificate> requiredCertificates;
    private boolean haveMinimumRouterInfo;
    private boolean needRecalculateMinimumRouterInfo;
    private final EventManager consensusChangedManager;
    private final TorRandom random;
    private final static DocumentParserFactory parserFactory = new DocumentParserFactoryImpl();

    private ConsensusDocument currentConsensus;
    private ConsensusDocument consensusWaitingForCertificates;

    public DirectoryImpl(TorConfig config, DirectoryStore customDirectoryStore) {
        store = (customDirectoryStore == null) ? (new DirectoryStoreImpl(config)) : (customDirectoryStore);
        this.config = config;
        stateFile = new StateFile(store, this);
        microdescriptorCache = createMicrodescriptorCache(store);
        basicDescriptorCache = createBasicDescriptorCache(store);	
        routersByIdentity = new HashMap<HexDigest, RouterImpl>();
        routersByNickname = new HashMap<String, RouterImpl>();
        directoryCaches = new RandomSet<RouterImpl>();
        requiredCertificates = new HashSet<ConsensusDocument.RequiredCertificate>();
        consensusChangedManager = new EventManager();
        random = new TorRandom();
    }

    private static DescriptorCache<RouterMicrodescriptor> createMicrodescriptorCache(DirectoryStore store) {
        return new DescriptorCache<RouterMicrodescriptor>(store, CacheFile.MICRODESCRIPTOR_CACHE, CacheFile.MICRODESCRIPTOR_JOURNAL) {
            @Override
            protected DocumentParser<RouterMicrodescriptor> createDocumentParser(ByteBuffer buffer) {
                return parserFactory.createRouterMicrodescriptorParser(buffer);
            }
        };
    }

    private static DescriptorCache<RouterDescriptor> createBasicDescriptorCache(DirectoryStore store) {
        return new DescriptorCache<RouterDescriptor>(store, CacheFile.DESCRIPTOR_CACHE, CacheFile.DESCRIPTOR_JOURNAL) {
            @Override
            protected DocumentParser<RouterDescriptor> createDocumentParser(ByteBuffer buffer) {
                return parserFactory.createRouterDescriptorParser(buffer, false);
            }
        };
    }

    public synchronized boolean haveMinimumRouterInfo() {
        if(needRecalculateMinimumRouterInfo) {
            checkMinimumRouterInfo();
        }
        return haveMinimumRouterInfo;
    }

    private synchronized void checkMinimumRouterInfo() {
        if(currentConsensus == null || !currentConsensus.isLive()) {
            needRecalculateMinimumRouterInfo = true;
            haveMinimumRouterInfo = false;
            return;
        }

        int routerCount = 0;
        int descriptorCount = 0;
        for(Router r: routersByIdentity.values()) {
            routerCount++;
            if(!r.isDescriptorDownloadable()){
                descriptorCount++;
            }
        }
        needRecalculateMinimumRouterInfo = false;
        haveMinimumRouterInfo = (descriptorCount * 4 > routerCount);
    }

    @Override
    public void loadFromStore() {
        logger.info("Loading cached network information from disk");

        synchronized(loadLock) {
            if(isLoaded) {
                return;
            }
            boolean useMicrodescriptors = config.getUseMicrodescriptors() != AutoBoolValue.FALSE;
            last = System.currentTimeMillis();
            logger.info("Loading certificates");
            loadCertificates(store.loadCacheFile(CacheFile.CERTIFICATES));
            logElapsed();

            logger.info("Loading consensus");
            loadConsensus(store.loadCacheFile(useMicrodescriptors ? CacheFile.CONSENSUS_MICRODESC : CacheFile.CONSENSUS));
            logElapsed();

            if(!useMicrodescriptors) {
                logger.info("Loading descriptors");
                basicDescriptorCache.initialLoad();
            } else {
                logger.info("Loading microdescriptor cache");
                microdescriptorCache.initialLoad();
            }
            needRecalculateMinimumRouterInfo = true;
            logElapsed();

            logger.info("loading state file");
            stateFile.parseBuffer(store.loadCacheFile(CacheFile.STATE));
            logElapsed();

            isLoaded = true;
            loadLock.notifyAll();
        }
    }

    @Override
    public void close() {
        basicDescriptorCache.shutdown();
        microdescriptorCache.shutdown();
    }

    private long last = 0;
    private void logElapsed() {
        final long now = System.currentTimeMillis();
        final long elapsed =  now - last;
        last = now;
        logger.debug("Loaded in "+ elapsed + " ms.");
    }

    private void loadCertificates(ByteBuffer buffer) {
        final DocumentParser<KeyCertificate> parser = parserFactory.createKeyCertificateParser(buffer);
        final DocumentParsingResult<KeyCertificate> result = parser.parse();
        if(testResult(result, "certificates")) {
            for(KeyCertificate cert: result.getParsedDocuments()) {
                addCertificate(cert);
            }
        }
    }

    private void loadConsensus(ByteBuffer buffer) {
        final DocumentParser<ConsensusDocument> parser = parserFactory.createConsensusDocumentParser(buffer);
        final DocumentParsingResult<ConsensusDocument> result = parser.parse();
        if(testResult(result, "consensus")) {
            addConsensusDocument(result.getDocument(), true);
        }
    }

    private boolean testResult(DocumentParsingResult<?> result, String type) {
        if(result.isOkay()) {
            return true;
        } else if(result.isError()) {
            logger.warn("Parsing error loading "+ type + " : "+ result.getMessage());
        } else if(result.isInvalid()) {
            logger.warn("Problem loading "+ type + " : "+ result.getMessage());
        } else {
            logger.warn("Unknown problem loading "+ type);
        }
        return false;
    }

    @Override
    public void waitUntilLoaded() {
        synchronized (loadLock) {
            while(!isLoaded) {
                try {
                    loadLock.wait();
                } catch (InterruptedException e) {
                    logger.warn("Thread interrupted while waiting for directory to load from disk");
                }
            }
        }
    }

    @Override
    public Collection<DirectoryServer> getDirectoryAuthorities() {
        return TrustedAuthorities.getInstance().getAuthorityServers();
    }

    /*
     * Only v3 directory authorities serve the consensus and the key
     * certificates; the bridge authority (Serge) does not and is never used
     * by clients for directory requests.
     */
    @Override
    public DirectoryServer getRandomDirectoryAuthority() {
        final List<DirectoryServer> servers = getV3Authorities();
        final int idx = random.nextInt(servers.size());
        return servers.get(idx);
    }

    private List<DirectoryServer> getV3Authorities() {
        final List<DirectoryServer> servers = new ArrayList<DirectoryServer>();
        for(DirectoryServer ds: TrustedAuthorities.getInstance().getAuthorityServers()) {
            if(ds.getV3Identity() != null) {
                servers.add(ds);
            }
        }
        return servers;
    }

    /*
     * Weights used to choose a bootstrap directory, scaled by 10.  As in Tor
     * (router_pick_fallback_dirserver(), DirAuthorityFallbackRate), each
     * authority is a tenth as likely to be picked as each fallback directory,
     * so with the built-in list the authorities get well under 1% of the
     * bootstrap requests.
     */
    private final static int FALLBACK_DIRECTORY_WEIGHT = 10;
    private final static int AUTHORITY_DIRECTORY_WEIGHT = 1;

    @Override
    public Router getRandomBootstrapDirectory() {
        final List<Router> fallbacks = FallbackDirectories.getInstance().getFallbackDirectories();
        final List<DirectoryServer> authorities = getV3Authorities();
        final int fallbackTotal = fallbacks.size() * FALLBACK_DIRECTORY_WEIGHT;
        final int total = fallbackTotal + authorities.size() * AUTHORITY_DIRECTORY_WEIGHT;
        final int r = random.nextInt(total);
        if(r < fallbackTotal) {
            return fallbacks.get(r / FALLBACK_DIRECTORY_WEIGHT);
        } else {
            return authorities.get((r - fallbackTotal) / AUTHORITY_DIRECTORY_WEIGHT);
        }
    }

    @Override
    public Set<ConsensusDocument.RequiredCertificate> getRequiredCertificates() {
        return new HashSet<ConsensusDocument.RequiredCertificate>(requiredCertificates);
    }

    @Override
    public void addCertificate(KeyCertificate certificate) {
        synchronized(TrustedAuthorities.getInstance()) {
            final boolean wasRequired = removeRequiredCertificate(certificate);
            final DirectoryServer as = TrustedAuthorities.getInstance().getAuthorityServerByIdentity(certificate.getAuthorityFingerprint());
            if(as == null) {
                logger.warn("Certificate read for unknown directory authority with identity: "+ certificate.getAuthorityFingerprint());
                return;
            }
            as.addCertificate(certificate);

            if(consensusWaitingForCertificates != null && wasRequired) {

                switch(consensusWaitingForCertificates.verifySignatures()) {
                case STATUS_FAILED:
                    consensusWaitingForCertificates = null;
                    return;

                case STATUS_VERIFIED:
                    addConsensusDocument(consensusWaitingForCertificates, false);
                    consensusWaitingForCertificates = null;
                    return;

                case STATUS_NEED_CERTS:
                    requiredCertificates.addAll(consensusWaitingForCertificates.getRequiredCertificates());
                    return;
                }
            }
        }
    }

    private boolean removeRequiredCertificate(KeyCertificate certificate) {
        final Iterator<RequiredCertificate> it = requiredCertificates.iterator();
        while(it.hasNext()) {
            RequiredCertificate r = it.next();
            if(r.getSigningKey().equals(certificate.getAuthoritySigningKey().getFingerprint())) {
                it.remove();
                return true;
            }
        }
        return false;
    }

    @Override
    public void storeCertificates() {
        synchronized(TrustedAuthorities.getInstance()) {
            final List<KeyCertificate> certs = new ArrayList<KeyCertificate>();
            for(DirectoryServer ds: TrustedAuthorities.getInstance().getAuthorityServers()) {
                certs.addAll(ds.getCertificates());
            }
            store.writeDocumentList(CacheFile.CERTIFICATES, certs);
        }
    }

    @Override
    public void addRouterDescriptors(List<RouterDescriptor> descriptors) {
        basicDescriptorCache.addDescriptors(descriptors);
        needRecalculateMinimumRouterInfo = true;
    }

    @Override
    public synchronized void addConsensusDocument(ConsensusDocument consensus, boolean fromCache) {
        if(consensus.equals(currentConsensus)){
            return;
        }

        if(currentConsensus != null && consensus.getValidAfterTime().isBefore(currentConsensus.getValidAfterTime())) {
            logger.warn("New consensus document is older than current consensus document");
            return;
        }

        synchronized(TrustedAuthorities.getInstance()) {
            switch(consensus.verifySignatures()) {
            case STATUS_FAILED:
                logger.warn("Unable to verify signatures on consensus document, discarding...");
                return;

            case STATUS_NEED_CERTS:
                consensusWaitingForCertificates = consensus;
                requiredCertificates.addAll(consensus.getRequiredCertificates());
                return;

            case STATUS_VERIFIED:
                break;
            }
            requiredCertificates.addAll(consensus.getRequiredCertificates());

        }
        final Map<HexDigest, RouterImpl> oldRouterByIdentity = new HashMap<HexDigest, RouterImpl>(routersByIdentity);

        clearAll();

        for(RouterStatus status: consensus.getRouterStatusEntries()) {
            if(status.hasFlag("Running") && status.hasFlag("Valid")) {
                final RouterImpl router = updateOrCreateRouter(status, oldRouterByIdentity);
                addRouter(router);
                classifyRouter(router);
            }
            final Descriptor d = getDescriptorForRouterStatus(status, consensus.getFlavor() == ConsensusFlavor.MICRODESC);
            if(d != null) {
                d.setLastListed(consensus.getValidAfterTime().getTime());
            }
        }

        logger.debug("Loaded "+ routersByIdentity.size() +" routers from consensus document");
        currentConsensus = consensus;

        if(!fromCache) {
            storeCurrentConsensus();
        }
        consensusChangedManager.fireEvent(new Event() {});
    }

    private void storeCurrentConsensus() {
        if(currentConsensus != null) {
            if(currentConsensus.getFlavor() == ConsensusFlavor.MICRODESC) {
                store.writeDocument(CacheFile.CONSENSUS_MICRODESC, currentConsensus);
            } else {
                store.writeDocument(CacheFile.CONSENSUS, currentConsensus);
            }
        }
    }

    private Descriptor getDescriptorForRouterStatus(RouterStatus rs, boolean isMicrodescriptor) {
        if(isMicrodescriptor) {
            return microdescriptorCache.getDescriptor(rs.getMicrodescriptorDigest());
        } else {
            return basicDescriptorCache.getDescriptor(rs.getDescriptorDigest());
        }
    }

    private RouterImpl updateOrCreateRouter(RouterStatus status, Map<HexDigest, RouterImpl> knownRouters) {
        final RouterImpl router = knownRouters.get(status.getIdentity());
        if(router == null){
            return RouterImpl.createFromRouterStatus(this, status);
        }
        router.updateStatus(status);
        return router;
    }

    private void clearAll() {
        routersByIdentity.clear();
        routersByNickname.clear();
        directoryCaches.clear();
    }

    private void classifyRouter(RouterImpl router) {
        if(isValidDirectoryCache(router)) {
            directoryCaches.add(router);
        } else {
            directoryCaches.remove(router);
        }
    }

    private boolean isValidDirectoryCache(RouterImpl router) {
        // Relays publish a DirPort of 0 since Tor 0.4.6 and serve directory
        // requests over BEGIN_DIR instead, so the DirPort is not checked.
        if(router.hasFlag("BadDirectory")){
            return false;
        }
        return router.hasFlag("V2Dir");
    }

    private void addRouter(RouterImpl router) {
        routersByIdentity.put(router.getIdentityHash(), router);
        addRouterByNickname(router);
    }

    private void addRouterByNickname(RouterImpl router) {
        final String name = router.getNickname();
        if(name == null || name.equals("Unnamed"))
            return;
        if(routersByNickname.containsKey(router.getNickname())) {
            //logger.warn("Duplicate router nickname: "+ router.getNickname());
            return;
        }
        routersByNickname.put(name, router);
    }

    @Override
    public synchronized void addRouterMicrodescriptors(List<RouterMicrodescriptor> microdescriptors) {
        microdescriptorCache.addDescriptors(microdescriptors);
        needRecalculateMinimumRouterInfo = true;
    }

    @Override
    synchronized public List<Router> getRoutersWithDownloadableDescriptors() {
        waitUntilLoaded();
        final List<Router> routers = new ArrayList<Router>();
        for(RouterImpl router: routersByIdentity.values()) {
            if(router.isDescriptorDownloadable()){
                routers.add(router);
            }
        }

        for(int i = 0; i < routers.size(); i++) {
            final Router a = routers.get(i);
            final int swapIdx = random.nextInt(routers.size());
            final Router b = routers.get(swapIdx);
            routers.set(i, b);
            routers.set(swapIdx, a);
        }

        return routers;
    }

    @Override
    public ConsensusDocument getCurrentConsensusDocument() {
        return currentConsensus;
    }

    @Override
    public boolean hasPendingConsensus() {
        synchronized (TrustedAuthorities.getInstance()) {
            return consensusWaitingForCertificates != null;	
        }
    }

    @Override
    public void registerConsensusChangedHandler(EventHandler handler) {
        consensusChangedManager.addListener(handler);
    }

    @Override
    public void unregisterConsensusChangedHandler(EventHandler handler) {
        consensusChangedManager.removeListener(handler);
    }

    @Override
    public Router getRouterByName(String name) {
        if(name.equals("Unnamed")) {
            return null;
        }
        if(name.length() == 41 && name.charAt(0) == '$') {
            try {
                final HexDigest identity = HexDigest.createFromString(name.substring(1));
                return getRouterByIdentity(identity);
            } catch (Exception e) {
                return null;
            }
        }
        waitUntilLoaded();
        return routersByNickname.get(name);
    }

    @Override
    public Router getRouterByIdentity(HexDigest identity) {
        waitUntilLoaded();
        synchronized (routersByIdentity) {
            return routersByIdentity.get(identity);
        }
    }

    @Override
    public List<Router> getRouterListByNames(List<String> names) {
        waitUntilLoaded();
        final List<Router> routers = new ArrayList<Router>();
        for(String n: names) {
            final Router r = getRouterByName(n);
            if(r == null){
                throw new TorException("Could not find router named: "+ n);
            }
            routers.add(r);
        }
        return routers;
    }

    @Override
    public List<Router> getAllRouters() {
        waitUntilLoaded();
        synchronized(routersByIdentity) {
            return new ArrayList<Router>(routersByIdentity.values());
        }
    }

    @Override
    public GuardEntry createGuardEntryFor(Router router) {
        waitUntilLoaded();
        return stateFile.createGuardEntryFor(router);
    }

    @Override
    public List<GuardEntry> getGuardEntries() {
        waitUntilLoaded();
        return stateFile.getGuardEntries();
    }

    @Override
    public void removeGuardEntry(GuardEntry entry) {
        waitUntilLoaded();
        stateFile.removeGuardEntry(entry);
    }

    @Override
    public void addGuardEntry(GuardEntry entry) {
        waitUntilLoaded();
        stateFile.addGuardEntry(entry);
    }

    @Override
    public RouterMicrodescriptor getMicrodescriptorFromCache(HexDigest descriptorDigest) {
        return microdescriptorCache.getDescriptor(descriptorDigest);
    }


    @Override
    public RouterDescriptor getBasicDescriptorFromCache(HexDigest descriptorDigest) {
        return basicDescriptorCache.getDescriptor(descriptorDigest);
    }
}
