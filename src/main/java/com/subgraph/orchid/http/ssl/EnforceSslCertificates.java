package com.subgraph.orchid.http.ssl;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.logging.Logger;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;

public class EnforceSslCertificates {
    private static final Logger logger = Logger.getInstance(EnforceSslCertificates.class);
    private static KeyStore KEY_STORE;

    static{
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            Path ksPath = Paths.get(System.getProperty("java.home"),"lib", "security", "cacerts");
            keyStore.load(new FileInputStream(ksPath.toFile()),"changeit".toCharArray());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for(ExportedCertificate exportedCertificate : ApplicationProperties.getAdditionalSslCertificates()){
                InputStream caInput = null;
                try{
                    caInput = new BufferedInputStream(EnforceSslCertificates.class.getResourceAsStream(exportedCertificate.getPath()+exportedCertificate.getName()+"."+exportedCertificate.getExtension()));
                    Certificate crt = cf.generateCertificate(caInput);
                    keyStore.setCertificateEntry(exportedCertificate.getName(), crt);
                } finally{
                    if(caInput!=null){
                        caInput.close();
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Unable to export ssl certificates.", e);
        } finally{
            KEY_STORE = keyStore;
        }
    }
    
    public static SSLContext getSSLContext(){
        try{
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(KEY_STORE);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            SSLContext.setDefault(sslContext);
            return sslContext;
        } catch(Exception e){
            return null;
        }
    }
}