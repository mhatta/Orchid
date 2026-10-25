package com.subgraph.orchid.http.ssl;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * A TLS context that accepts any certificate for any host.
 *
 * @deprecated Over Tor, the exit relay can read and modify every connection
 * made with this context.  It remains only for compatibility with
 * {@link com.subgraph.orchid.http.TorRequest#setEnforceSslCertificates(Boolean)}
 * set to false, and will be removed in a later release.
 */
@Deprecated
public class IgnoreSslCertificates {
    public static SSLContext getSSLContext() {
        try{
            // An X509ExtendedTrustManager, so that JSSE does not wrap it and
            // add a host name check: this context deliberately checks nothing.
            TrustManager tm = new X509ExtendedTrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] { tm }, null);
            return sslContext;
        } catch(Exception e){
            //swallow
            return null;
        }
    }
}