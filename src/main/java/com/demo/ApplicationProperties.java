package com.demo;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import com.subgraph.orchid.http.ssl.ExportedCertificate;
import com.subgraph.orchid.logging.SysLog;

public class ApplicationProperties {
    private static final String NAME = "Orchid";
    /*
     * Written by the Gradle build from the git release tag (see build.gradle);
     * there is no version number to update by hand.  The resource lives in
     * Orchid's package rather than at the classpath root so that it cannot
     * be shadowed by a file of the application that uses Orchid.
     */
    static final String VERSION_RESOURCE = "/com/subgraph/orchid/version.properties";
    static final String UNKNOWN_VERSION = "unknown";
    private static final String VERSION = loadVersion();
    /** System property selecting the log level, e.g. -Dcom.subgraph.orchid.logLevel=DEBUG */
    public static final String LOG_LEVEL_PROPERTY = "com.subgraph.orchid.logLevel";
    private static SysLog LOGGING_THRESHOLD = initialLoggingThreshold();
    private static boolean USE_COMPRESSION = false;
    private static boolean ENFORCE_SSL_CERTIFICATES = true;
    private static String[] TRUSTED_DIRECTORY_AUTHORITIES = {

	// Kept in sync with src/app/config/auth_dirs.inc of the Tor source.
	// Last updated 2026-10: moria1 (new keys and ports, 2023), tor26 (new keys
	// and address, 2024), dizum (new address) and faravahar (re-added with new
	// keys and address; replaces the retired "Faravahar" entry).
	"authority moria1 orport=9201 v3ident=F533C81CEF0BC0267857C99B2F471ADF249FA232 128.31.0.39:9231 1A25 C635 8DB9 1342 AA51 720A 5038 B727 4273 2498",
	"authority tor26 orport=443 v3ident=2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C ipv6=[2a02:16a8:662:2203::1]:443 217.196.147.77:80 FAA4 BCA4 A6AC 0FB4 CA2F 8AD5 A11D 9E12 2BA8 94F6",
	"authority dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 45.66.35.11:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
	"authority Serge orport=9001 bridge 66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533",
	"authority gabelmoo orport=443 v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 ipv6=[2001:638:a000:4140::ffff:189]:443 131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
	"authority dannenberg orport=443 v3ident=0232AF901C31A04EE9848595AF9BB7620D4C5B2E ipv6=[2001:678:558:1000::244]:443 193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
	"authority maatuska orport=80 v3ident=49015F787433103580E3B66A1707A00E60F2D15B ipv6=[2001:67c:289c::9]:80 171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
	"authority longclaw orport=443 v3ident=23D15D965BC35114467363C165C4F724B64B4F66 199.58.81.140:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145",
	"authority bastet orport=443 v3ident=27102BC123E7AF1D4741AE047E160C91ADC76B21 ipv6=[2620:13:4000:6000::1000:118]:443 204.13.164.118:80 24E2 F139 121D 4394 C54B 5BCC 368B 3B41 1857 C413",
	"authority faravahar orport=443 v3ident=70849B868D606BAECFB6128C5E3D782029AA394F 216.218.219.41:80 E3E4 2D35 F801 C9D5 AB23 584E 0025 D56F E2B3 3396"

    };
    
    //Import common SSL certificates that are not system defaults
    private static ExportedCertificate[] ADDITIONAL_SSL_CERTIFICATES = {
        ExportedCertificate.getInstance("/com/subgraph/orchid/http/ssl/certificates/", "DSTRootCAX3", "der"),
        ExportedCertificate.getInstance("/com/subgraph/orchid/http/ssl/certificates/", "StartComCertificationAuthority", "der")
    };
    
    public static String getName(){
        return NAME;
    }
    
    /**
     * The version of this build, e.g. "2.0.0" for a release or
     * "2.0.0-3-g1234abcd" for a later commit, or "unknown" when Orchid was
     * not built with Gradle.
     */
    public static String getVersion(){
        return VERSION;
    }

    private static String loadVersion(){
        final InputStream input = ApplicationProperties.class.getResourceAsStream(VERSION_RESOURCE);
        if(input == null){
            return UNKNOWN_VERSION;
        }
        try {
            return parseVersion(input);
        } finally {
            try {
                input.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    static String parseVersion(InputStream input){
        final Properties properties = new Properties();
        try {
            properties.load(input);
        } catch (IOException e) {
            return UNKNOWN_VERSION;
        } catch (IllegalArgumentException e) {
            return UNKNOWN_VERSION;
        }
        final String version = properties.getProperty("version");
        if(version == null || version.trim().isEmpty() || version.trim().indexOf(' ') >= 0){
            // The state file stores "<name>-<version>" as one token.
            return UNKNOWN_VERSION;
        }
        return version.trim();
    }
    
    private static SysLog initialLoggingThreshold(){
        final SysLog fromProperty = SysLog.forName(System.getProperty(LOG_LEVEL_PROPERTY));
        return (fromProperty != null) ? fromProperty : SysLog.INFORMATIONAL;
    }

    public static SysLog getLoggingThreshold(){
        return LOGGING_THRESHOLD;
    }
    
    public static void setLoggingThreshold(SysLog loggingThreshold){
        LOGGING_THRESHOLD = loggingThreshold;
    }
    
    public static boolean getUseCompression(){
        return USE_COMPRESSION;
    }
    
    public static void setUseCompression(boolean useCompression){
        USE_COMPRESSION = useCompression;
    }
    
    public static boolean getEnforceSslCertificates(){
        return ENFORCE_SSL_CERTIFICATES;
    }
    
    public static void setEnforceSslCertificates(boolean enforceSslCertificates){
        ENFORCE_SSL_CERTIFICATES = enforceSslCertificates;
    }
    
    public static String[] getTrustedDirectoryAuthorities(){
        return TRUSTED_DIRECTORY_AUTHORITIES;
    }
    
    public static void setTrustedDirectoryAuthorities(String[] trustedDirectoryAuthorities){
        TRUSTED_DIRECTORY_AUTHORITIES = trustedDirectoryAuthorities;
    }
    
    public static ExportedCertificate[] getAdditionalSslCertificates(){
        return ADDITIONAL_SSL_CERTIFICATES;
    }
    
    public static void setAdditionalSslCertificates(ExportedCertificate[] additionalSslCertificates){
        ADDITIONAL_SSL_CERTIFICATES = additionalSslCertificates;
    }
}
