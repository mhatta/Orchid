package com.demo;

import com.subgraph.orchid.http.TorRequest;
import com.subgraph.orchid.logging.Logger;

public class Grab {
    private static final Logger logger = Logger.getInstance(Grab.class);
    
    public static void main(String[] args) throws Exception {
        try{
            TorRequest.openTunnel();
            TorRequest whatIsMyIp = TorRequest.getInstance("http://ip-api.com/json");
            whatIsMyIp.executeRequest();
            logger.info(whatIsMyIp.getResponse().getContent());
        } finally{
            TorRequest.closeTunnel();
        }
    }
}