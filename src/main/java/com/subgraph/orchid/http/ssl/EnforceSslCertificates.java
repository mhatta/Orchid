package com.subgraph.orchid.http.ssl;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.logging.Logger;

/**
 * The TLS context of {@link com.subgraph.orchid.http.TorRequest} when
 * certificates are checked: the platform's trust store, plus the
 * certificates in {@link ApplicationProperties#getAdditionalSslCertificates()}
 * if there are any (there are none by default).
 */
public class EnforceSslCertificates {
    private static final Logger logger = Logger.getInstance(EnforceSslCertificates.class);

    public static SSLContext getSSLContext(){
        try{
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(createTrustStore());
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext;
        } catch(Exception e){
            logger.error("Unable to create the TLS context", e);
            return null;
        }
    }

    /*
     * null selects the platform's default trust store (which honours
     * javax.net.ssl.trustStore and works on Android).  Only when extra
     * certificates are configured is the JDK's cacerts file loaded and
     * extended with them.
     */
    private static KeyStore createTrustStore() throws GeneralSecurityException, IOException {
        final ExportedCertificate[] additional = ApplicationProperties.getAdditionalSslCertificates();
        if(additional == null || additional.length == 0) {
            return null;
        }
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        final Path ksPath = Paths.get(System.getProperty("java.home"), "lib", "security", "cacerts");
        final InputStream ksInput = new FileInputStream(ksPath.toFile());
        try {
            keyStore.load(ksInput, "changeit".toCharArray());
        } finally {
            ksInput.close();
        }

        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for(ExportedCertificate exportedCertificate : additional){
            final String resource = exportedCertificate.getPath() + exportedCertificate.getName() + "." + exportedCertificate.getExtension();
            final InputStream resourceInput = EnforceSslCertificates.class.getResourceAsStream(resource);
            if(resourceInput == null) {
                throw new IOException("Certificate resource not found: "+ resource);
            }
            final InputStream caInput = new BufferedInputStream(resourceInput);
            try{
                final Certificate crt = cf.generateCertificate(caInput);
                keyStore.setCertificateEntry(exportedCertificate.getName(), crt);
            } finally{
                caInput.close();
            }
        }
        return keyStore;
    }
}
