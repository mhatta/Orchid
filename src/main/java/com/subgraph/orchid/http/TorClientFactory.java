package com.subgraph.orchid.http;

import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.TorInitializationListener;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.directory.DocumentFieldParserImpl;
import com.subgraph.orchid.directory.TrustedAuthorities;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.logging.Logger;

public class TorClientFactory {
    private static final Logger logger = Logger.getInstance(TorClientFactory.class);
    private static final int PROXY_PORT = 9150;
    private static final String PROXY_HOST = "localhost";
    private static TorClient client;
    private static boolean isStarting = false;
    private static boolean isRunning = false;
    
    public static TorClient getTorClient(){
        return client;
    }
    
    public static boolean hasOpenTorTunnel(){
        return isStarting || isRunning;
    }
    
    @SuppressWarnings("deprecation")
    public static void openTunnel(){
        if(!isRunning){
            isStarting = true;
            if(TorCryptography.hasRestrictedCryptography()){
                // Version 3 onion services need AES-256.
                logger.warn("This Java runtime limits AES keys to less than 256 bits; update Java (8u161 or later)");
            }
            client = new TorClient();
            client.enableSocksListener(PROXY_PORT);
            client.addInitializationListener(createInitalizationListner());
            client.start();
            client.enableSocksListener();
        }
        while(!isRunning){
            try{
                Thread.sleep(1000l);
            } catch(Exception e){
                //swallow
            }
        }
    }
    
    public static Proxy getProxy(){
        return new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(PROXY_HOST, PROXY_PORT));
    }
    
    public static void closeTunnel(){
        while(isStarting){
            try{
                Thread.sleep(100l);
            } catch(Exception e){
                //swallow
            }
        }
        client.stop();
        client = null;
        isRunning = false;
        isStarting = false;
    }
    
    private static TorInitializationListener createInitalizationListner() {
        return new TorInitializationListener() {
            @Override
            public void initializationProgress(String message, int percent) {
                logger.info(">>> [ " + percent + "% ]: " + message);
            }

            @Override
            public void initializationCompleted() {
                logger.info("Tor is ready to go!");
                isRunning = true;
                isStarting = false;
            }
        };
    }
}