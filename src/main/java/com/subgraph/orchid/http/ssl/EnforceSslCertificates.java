package com.subgraph.orchid.http.ssl;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

import com.subgraph.orchid.ApplicationProperties;
import com.subgraph.orchid.logging.Logger;

/**
 * The TLS context of {@link com.subgraph.orchid.http.TorRequest} when
 * certificates are checked: the platform's trust store, plus the
 * certificates in {@link ApplicationProperties#getAdditionalSslCertificates()}
 * if there are any (there are none by default).
 *
 * The platform's trust store is whatever the default TrustManagerFactory
 * uses: the JDK's cacerts file or <code>javax.net.ssl.trustStore</code>, or
 * the system (and, as the app's network security configuration allows, the
 * user) certificates on Android.  The additional certificates are checked
 * by a second trust manager when the platform does not trust the server,
 * so no key store file is read and nothing here needs
 * <code>java.nio.file</code> (Android API level 26).
 */
public class EnforceSslCertificates {
    private static final Logger logger = Logger.getInstance(EnforceSslCertificates.class);

    public static SSLContext getSSLContext(){
        try{
            return createSSLContext(loadAdditionalCertificates());
        } catch(Exception e){
            logger.error("Unable to create the TLS context", e);
            return null;
        }
    }

    static SSLContext createSSLContext(List<X509Certificate> additional) throws GeneralSecurityException, IOException {
        final X509ExtendedTrustManager platform = getTrustManager(null);
        final TrustManager trustManager;
        if(additional.isEmpty()) {
            trustManager = platform;
        } else {
            final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            for(int i = 0; i < additional.size(); i++) {
                keyStore.setCertificateEntry("additional-"+ i, additional.get(i));
            }
            trustManager = new CombinedTrustManager(platform, getTrustManager(keyStore));
        }
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[] { trustManager }, null);
        return sslContext;
    }

    /* null selects the platform's default trust store. */
    private static X509ExtendedTrustManager getTrustManager(KeyStore keyStore) throws GeneralSecurityException {
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        for(TrustManager tm: tmf.getTrustManagers()) {
            if(tm instanceof X509ExtendedTrustManager) {
                return (X509ExtendedTrustManager) tm;
            }
        }
        throw new GeneralSecurityException("No X509ExtendedTrustManager from "+ tmf.getAlgorithm());
    }

    private static List<X509Certificate> loadAdditionalCertificates() throws GeneralSecurityException, IOException {
        final List<X509Certificate> certificates = new ArrayList<X509Certificate>();
        final ExportedCertificate[] additional = ApplicationProperties.getAdditionalSslCertificates();
        if(additional == null) {
            return certificates;
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
                certificates.add((X509Certificate) cf.generateCertificate(caInput));
            } finally{
                caInput.close();
            }
        }
        return certificates;
    }

    /*
     * Trusts what the platform trusts, and what the additional certificates
     * trust.  Both are X509ExtendedTrustManagers, so the host name check
     * that SSLEngineSSLSocket asks for (endpoint identification) is done
     * whichever of them accepts the server.
     */
    static class CombinedTrustManager extends X509ExtendedTrustManager {
        private final X509ExtendedTrustManager platform;
        private final X509ExtendedTrustManager additional;

        CombinedTrustManager(X509ExtendedTrustManager platform, X509ExtendedTrustManager additional) {
            this.platform = platform;
            this.additional = additional;
        }

        private interface Check {
            void run(X509ExtendedTrustManager tm) throws CertificateException;
        }

        private void checkEither(Check check) throws CertificateException {
            try {
                check.run(platform);
            } catch(CertificateException e) {
                try {
                    check.run(additional);
                } catch(CertificateException e2) {
                    e.addSuppressed(e2);
                    throw e;
                }
            }
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
            checkEither(new Check() {
                public void run(X509ExtendedTrustManager tm) throws CertificateException {
                    tm.checkServerTrusted(chain, authType);
                }
            });
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType, final Socket socket) throws CertificateException {
            checkEither(new Check() {
                public void run(X509ExtendedTrustManager tm) throws CertificateException {
                    tm.checkServerTrusted(chain, authType, socket);
                }
            });
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType, final SSLEngine engine) throws CertificateException {
            checkEither(new Check() {
                public void run(X509ExtendedTrustManager tm) throws CertificateException {
                    tm.checkServerTrusted(chain, authType, engine);
                }
            });
        }

        // Orchid is only ever the client.
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            platform.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            platform.checkClientTrusted(chain, authType, socket);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            platform.checkClientTrusted(chain, authType, engine);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            final Set<X509Certificate> issuers = new LinkedHashSet<X509Certificate>();
            issuers.addAll(Arrays.asList(platform.getAcceptedIssuers()));
            issuers.addAll(Arrays.asList(additional.getAcceptedIssuers()));
            return issuers.toArray(new X509Certificate[issuers.size()]);
        }
    }
}
