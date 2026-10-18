package com.subgraph.orchid.directory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.Logger;

/**
 * The built-in fallback directories (see {@link FallbackDirectoryList}).
 *
 * Tor clients bootstrap from these relays rather than from the directory
 * authorities, which are few, heavily loaded and limit the connections they
 * accept from clients.  They are only used until a consensus is available;
 * after that, directory documents are fetched from the directory caches
 * listed in the consensus.
 */
public class FallbackDirectories {
    private static final Logger logger = Logger.getInstance(FallbackDirectories.class);

    private final static FallbackDirectories _instance = new FallbackDirectories(FallbackDirectoryList.FALLBACK_DIRECTORIES);

    public static FallbackDirectories getInstance() {
        return _instance;
    }

    private final List<Router> fallbacks;

    FallbackDirectories(String[] entries) {
        final List<Router> list = new ArrayList<Router>();
        for(String entry: entries) {
            try {
                list.add(parseEntry(entry));
            } catch(RuntimeException e) {
                logger.warn("Ignoring malformed fallback directory entry '"+ entry + "': "+ e.getMessage());
            }
        }
        fallbacks = Collections.unmodifiableList(list);
    }

    /*
     * "address:orport identity [nickname]"
     */
    static Router parseEntry(String entry) {
        final String[] parts = entry.trim().split("\\s+");
        if(parts.length < 2) {
            throw new IllegalArgumentException("expected 'address:orport identity [nickname]'");
        }
        final int colon = parts[0].lastIndexOf(':');
        if(colon <= 0) {
            throw new IllegalArgumentException("missing ORPort");
        }
        final IPv4Address address = IPv4Address.createFromString(parts[0].substring(0, colon));
        final int port = Integer.parseInt(parts[0].substring(colon + 1));
        if(port <= 0 || port > 65535) {
            throw new IllegalArgumentException("bad ORPort "+ port);
        }
        if(!parts[1].matches("[0-9A-Fa-f]{40}")) {
            throw new IllegalArgumentException("bad identity fingerprint");
        }
        final DirectoryAuthorityStatus status = DirectoryAuthorityStatus.createFallbackStatus();
        status.setNickname((parts.length > 2) ? parts[2] : "Unnamed");
        status.setAddress(address);
        status.setRouterPort(port);
        status.setIdentity(HexDigest.createFromString(parts[1]));
        return RouterImpl.createFromRouterStatus(null, status);
    }

    public List<Router> getFallbackDirectories() {
        return fallbacks;
    }
}
