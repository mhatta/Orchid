package com.subgraph.orchid.http;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.http.get.TorGetRequest;
import com.subgraph.orchid.http.post.TorPostRequest;
import com.subgraph.orchid.http.ssl.EnforceSslCertificates;
import com.subgraph.orchid.http.ssl.IgnoreSslCertificates;
import com.subgraph.orchid.logging.Logger;
import java.util.List;
import javax.net.ssl.SSLContext;

public abstract class TorRequest {
    private static final Logger logger = Logger.getInstance(TorRequest.class);
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

    @SuppressWarnings("deprecation")
    public SSLContext getSslContext() {
        if(enforceSslCertificates){
            return EnforceSslCertificates.getSSLContext();
        } else{
            logger.warn("TLS certificate checking is disabled: the Tor exit relay can read and modify this connection");
            return IgnoreSslCertificates.getSSLContext();
        }
    }
    
    /**
     * Whether the server's certificate chain must be trusted (true, the
     * default from {@link ApplicationProperties#getEnforceSslCertificates()}).
     *
     * <p>false accepts a certificate from any issuer, a self-signed one
     * included, but since 2.5.2 the certificate must still be valid for the
     * host name of the URL: {@link com.subgraph.orchid.sockets.sslengine.SSLEngineSSLSocket}
     * checks the name whatever this setting.  A server whose certificate
     * names another host, which 2.5.1 and earlier accepted here, is refused.
     * Without that check, false would let any exit relay answer with a
     * certificate of its own making; it remains unsafe all the same, as the
     * exit relay can still present a self-signed certificate for the right
     * name.  To trust a particular server, add its certificate with
     * {@link ApplicationProperties#setAdditionalSslCertificates} and keep
     * this true.
     */
    public TorRequest setEnforceSslCertificates(Boolean enforceSslCertificates){
        this.enforceSslCertificates = enforceSslCertificates;
        return this;
    }
}