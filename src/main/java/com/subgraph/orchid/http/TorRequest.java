package com.subgraph.orchid.http;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.http.get.TorGetRequest;
import com.subgraph.orchid.http.post.TorPostRequest;
import com.subgraph.orchid.http.ssl.EnforceSslCertificates;
import com.subgraph.orchid.http.ssl.IgnoreSslCertificates;
import java.util.List;
import javax.net.ssl.SSLContext;

public abstract class TorRequest {
    protected final String url;
    protected int maxRetryAttempts = 3;
    protected TorSocketStream request;
    protected HttpResponse response;
    private boolean enforceSslCertificates = ApplicationProperties.getEnforceSslCertificates();
    
    protected TorRequest(String url){
        this.url = url;
    }
    
    public static TorRequest getInstance(String url){
        return TorGetRequest.getInstance(url);
    }
    
    public static TorRequest getInstance(String url, List<NameValuePair> params){
        return TorPostRequest.getInstance(url, params);
    }
    
    public static void openTunnel(){
        TorClientFactory.openTunnel();
    }
    
    public void executeRequest() throws Exception{
        if(!TorClientFactory.hasOpenTorTunnel()){
            throw new Exception("Please do TorRequest.openTunnel() before "
                    + "making an http request over the tor network. Don't "
                    + "forget to do TorRequest.closeTunnel() when you "
                    + "are finished making requests over the tunnel.");
        }

        request.executeRequest();
        response = HttpResponse.getInstance(request);
        int currentRetryAttempts = 0;
        while(currentRetryAttempts<maxRetryAttempts && response.getStatusLine().getStatusCode()>399){
            request.executeRequest();
            response = HttpResponse.getInstance(request);
            currentRetryAttempts++;
        }
    }
    
    public HttpResponse getResponse(){
        return this.response;
    }
    
    public static void closeTunnel(){
        TorClientFactory.closeTunnel();
    }

    public TorRequest setMaxRetryAttempts(int maxRetryAttempts) {
        this.maxRetryAttempts = maxRetryAttempts;
        return this;
    }

    public SSLContext getSslContext() {
        if(enforceSslCertificates){
            return EnforceSslCertificates.getSSLContext();
        } else{
            return IgnoreSslCertificates.getSSLContext();
        }
    }
    
    public TorRequest setEnforceSslCertificates(Boolean enforceSslCertificates){
        this.enforceSslCertificates = enforceSslCertificates;
        return this;
    }
}