package com.demo;



import com.subgraph.orchid.http.NameValuePair;
import com.subgraph.orchid.http.HttpHeader;
import com.subgraph.orchid.http.TorRequest;
import com.subgraph.orchid.logging.Logger;
import java.util.*;

public class GrabPost {
    private static final Logger logger = Logger.getInstance(GrabPost.class);

    public static void main(String[] args) throws Exception {
        try{
            String url = "http://putsreq.com/pJ0XmJetHeDcMAWgC8gM";
            List<NameValuePair> params = new ArrayList();
            params.add(NameValuePair.getInstance("name","tor"));

            TorRequest.openTunnel();
            TorRequest request = TorRequest.getInstance(url, params);
            request.setMaxRetryAttempts(50);
            request.executeRequest();
            for(HttpHeader header : request.getResponse().getHeaders()){
                logger.info(header.getName()+"="+header.getValue());
            }
            logger.info(request.getResponse().getContent());
            logger.info(request.getResponse().getStatusLine().getStatusCode());
        } finally{
            TorRequest.closeTunnel();
        }
    }
}