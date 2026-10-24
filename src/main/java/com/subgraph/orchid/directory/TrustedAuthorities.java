package com.subgraph.orchid.directory;

import com.subgraph.orchid.ApplicationProperties;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;

/**
 * This class brings in the 'bootstrap' directory authority server information. 
 */
public class TrustedAuthorities {
    private final List<DirectoryServer> directoryServers = new ArrayList<DirectoryServer>();
    private final int v3ServerCount;

    private final static TrustedAuthorities _instance = new TrustedAuthorities();

    public static TrustedAuthorities getInstance() {
        return _instance;
    }
	
    private TrustedAuthorities() {
    	initialize();
    	v3ServerCount = countV3Servers();
    }
    
    private int countV3Servers() {
        int n = 0;
        for(DirectoryServer ds: directoryServers) {
            if(ds.getV3Identity() != null) {
                n += 1;
            }
        }
        return n;
    }
    
    void initialize() {
        final StringBuilder builder = new StringBuilder();
        for(String entry: ApplicationProperties.getTrustedDirectoryAuthorities()) {
            builder.append(entry);
            builder.append('\n');
        }
        final ByteBuffer buffer = ByteBuffer.wrap(builder.toString().getBytes(Tor.getDefaultCharset()));
        final DocumentFieldParser parser = new DocumentFieldParserImpl(buffer);

        parser.setHandler(new DocumentParsingHandler() {
            public void endOfDocument() {}
            public void parseKeywordLine() { processKeywordLine(parser);}
        });
        parser.processDocument();
    }
	
    private void processKeywordLine(DocumentFieldParser fieldParser) {
        final DirectoryAuthorityStatus status = new DirectoryAuthorityStatus();
        status.setNickname(fieldParser.parseNickname());
        while(fieldParser.argumentsRemaining() > 0) {
                processArgument(fieldParser, status);
        }
    }
	
    private void processArgument(DocumentFieldParser fieldParser, DirectoryAuthorityStatus status) {
        final String item = fieldParser.parseString();
        if(Character.isDigit(item.charAt(0))) {
            parseAddressPort(fieldParser, item, status);
            status.setIdentity(fieldParser.parseFingerprint());
            DirectoryServerImpl server = new DirectoryServerImpl(status);
            if(status.getV3Ident() != null) {
                    server.setV3Ident(status.getV3Ident());
            }
            fieldParser.logDebug("Adding trusted authority: " + server);
            directoryServers.add(server);
            return;
        } else {
            parseFlag(fieldParser, item, status);
        }
    }
	
    private void parseAddressPort(DocumentFieldParser parser, String item, DirectoryAuthorityStatus status) {
        final String[] args = item.split(":");
        status.setAddress(IPv4Address.createFromString(args[0]));
        status.setDirectoryPort(parser.parsePort(args[1]));	
    }
	
    private void parseFlag(DocumentFieldParser parser, String flag, DirectoryAuthorityStatus status) {
        if(flag.equals("v1")) {
            status.setV1Authority();
            status.setHiddenServiceAuthority();
        } else if(flag.equals("hs")) {
            status.setHiddenServiceAuthority();
        } else if(flag.equals("no-hs")) {
            status.unsetHiddenServiceAuthority();
        } else if(flag.equals("bridge")) {
            status.setBridgeAuthority();
        } else if(flag.equals("no-v2")) {
            status.unsetV2Authority();
        } else if(flag.startsWith("orport=")) {
            status.setRouterPort( parser.parsePort(flag.substring(7)));
        } else if(flag.startsWith("v3ident=")) {
            status.setV3Ident(HexDigest.createFromString(flag.substring(8)));
        }
    }
	
    public int getV3AuthorityServerCount() {
        return v3ServerCount;
    }

    public List<DirectoryServer> getAuthorityServers() {
        return directoryServers;
    }

    public DirectoryServer getAuthorityServerByIdentity(HexDigest identity) {
        for(DirectoryServer ds: directoryServers) {
            if(identity.equals(ds.getV3Identity())) {
                return ds;
            }
        }
        return null;
    }
}