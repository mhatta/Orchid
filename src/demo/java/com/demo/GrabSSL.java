package com.demo;



import com.subgraph.orchid.http.TorRequest;
import com.subgraph.orchid.logging.Logger;

public class GrabSSL {
    private static final Logger logger = Logger.getInstance(GrabSSL.class);
    
    public static void main(String[] args) throws Exception {
        try{
            TorRequest.openTunnel();
            TorRequest whatIsMyIpSSL = TorRequest.getInstance("https://wtfismyip.com/json");
            whatIsMyIpSSL.executeRequest();
            logger.info(whatIsMyIpSSL.getResponse().getContent());
        } finally{
            TorRequest.closeTunnel();
        }
    }
}