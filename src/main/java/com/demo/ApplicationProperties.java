package com.demo;

import com.subgraph.orchid.http.ssl.ExportedCertificate;
import com.subgraph.orchid.logging.SysLog;

/**
 * @deprecated Moved to {@link com.subgraph.orchid.ApplicationProperties}.
 * This class only forwards to it and will be removed in a later release.
 */
@Deprecated
public final class ApplicationProperties {
    public static final String LOG_LEVEL_PROPERTY = com.subgraph.orchid.ApplicationProperties.LOG_LEVEL_PROPERTY;

    private ApplicationProperties() {
    }

    public static String getName() {
        return com.subgraph.orchid.ApplicationProperties.getName();
    }

    public static String getVersion() {
        return com.subgraph.orchid.ApplicationProperties.getVersion();
    }

    public static SysLog getLoggingThreshold() {
        return com.subgraph.orchid.ApplicationProperties.getLoggingThreshold();
    }

    public static void setLoggingThreshold(SysLog loggingThreshold) {
        com.subgraph.orchid.ApplicationProperties.setLoggingThreshold(loggingThreshold);
    }

    public static boolean getUseCompression() {
        return com.subgraph.orchid.ApplicationProperties.getUseCompression();
    }

    public static void setUseCompression(boolean useCompression) {
        com.subgraph.orchid.ApplicationProperties.setUseCompression(useCompression);
    }

    public static boolean getEnforceSslCertificates() {
        return com.subgraph.orchid.ApplicationProperties.getEnforceSslCertificates();
    }

    public static void setEnforceSslCertificates(boolean enforceSslCertificates) {
        com.subgraph.orchid.ApplicationProperties.setEnforceSslCertificates(enforceSslCertificates);
    }

    public static String[] getTrustedDirectoryAuthorities() {
        return com.subgraph.orchid.ApplicationProperties.getTrustedDirectoryAuthorities();
    }

    public static void setTrustedDirectoryAuthorities(String[] trustedDirectoryAuthorities) {
        com.subgraph.orchid.ApplicationProperties.setTrustedDirectoryAuthorities(trustedDirectoryAuthorities);
    }

    public static ExportedCertificate[] getAdditionalSslCertificates() {
        return com.subgraph.orchid.ApplicationProperties.getAdditionalSslCertificates();
    }

    public static void setAdditionalSslCertificates(ExportedCertificate[] additionalSslCertificates) {
        com.subgraph.orchid.ApplicationProperties.setAdditionalSslCertificates(additionalSslCertificates);
    }
}
