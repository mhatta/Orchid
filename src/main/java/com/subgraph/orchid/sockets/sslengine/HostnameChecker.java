package com.subgraph.orchid.sockets.sslengine;

import java.net.IDN;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * Checks that a server certificate was issued for the host name the client
 * asked for (RFC 6125, as browsers and OkHttp apply it).
 *
 * SSLEngineSSLSocket also asks the SSLEngine for this check
 * (setEndpointIdentificationAlgorithm("HTTPS")), but whether the engine
 * does it depends on the platform and on the trust manager: Android's
 * engines do not promise it.  Over Tor the exit relay sits between the
 * client and the server, and a certificate that is trusted but issued for
 * another name must not be accepted, so the check is made here as well.
 *
 * The rules:
 * <ul>
 * <li>A host name matches a dNSName subject alternative name, compared
 * without regard to case and to a final dot.  Names that are not ASCII are
 * compared in their IDNA (A-label) form.</li>
 * <li>A wildcard matches only as the whole leftmost label
 * ("*.example.com"), stands for exactly one label, and needs at least two
 * labels after it, so "*.com" matches nothing.</li>
 * <li>An IPv4 literal matches an iPAddress subject alternative name.  IPv6
 * literals are refused: Orchid does not open streams to them.</li>
 * <li>The subject's common name is not used.</li>
 * </ul>
 *
 * Nothing here resolves names, so no host name reaches the device's DNS.
 */
public final class HostnameChecker {
    private static final int SAN_DNS_NAME = 2;
    private static final int SAN_IP_ADDRESS = 7;

    private HostnameChecker() {}

    /**
     * Throw SSLPeerUnverifiedException unless the leaf certificate of
     * session was issued for host.
     */
    public static void verify(String host, SSLSession session) throws SSLPeerUnverifiedException {
        final Certificate[] chain = session.getPeerCertificates();
        if(chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
            throw new SSLPeerUnverifiedException("No X.509 certificate from the server");
        }
        if(!matches(host, (X509Certificate) chain[0])) {
            throw new SSLPeerUnverifiedException("The server's certificate was not issued for the host name asked for");
        }
    }

    /** True if certificate was issued for host. */
    public static boolean matches(String host, X509Certificate certificate) {
        if(host == null || host.isEmpty()) {
            return false;
        }
        if(host.startsWith("[") || host.indexOf(':') >= 0) {
            return false;
        }
        final byte[] ipv4 = parseIPv4(host);
        final Collection<List<?>> names;
        try {
            names = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return false;
        }
        if(names == null) {
            return false;
        }
        if(ipv4 != null) {
            return matchesIPv4(ipv4, names);
        }
        final String name = normalize(host);
        if(name == null) {
            return false;
        }
        for(List<?> entry: names) {
            if(entry.size() < 2 || !(entry.get(0) instanceof Integer) || !(entry.get(1) instanceof String)) {
                continue;
            }
            if(((Integer) entry.get(0)) == SAN_DNS_NAME && matchesDnsName(name, (String) entry.get(1))) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesIPv4(byte[] address, Collection<List<?>> names) {
        for(List<?> entry: names) {
            if(entry.size() < 2 || !(entry.get(0) instanceof Integer) || !(entry.get(1) instanceof String)) {
                continue;
            }
            if(((Integer) entry.get(0)) != SAN_IP_ADDRESS) {
                continue;
            }
            final byte[] san = parseIPv4((String) entry.get(1));
            if(san != null && java.util.Arrays.equals(address, san)) {
                return true;
            }
        }
        return false;
    }

    /* Lower case ASCII without a final dot, or null if the name is not usable. */
    private static String normalize(String name) {
        String s = name;
        if(s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        if(s.isEmpty() || s.startsWith(".") || s.contains("..")) {
            return null;
        }
        if(!isAscii(s)) {
            try {
                s = IDN.toASCII(s);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return s.toLowerCase(Locale.ROOT);
    }

    private static boolean matchesDnsName(String host, String pattern) {
        final String p = normalize(pattern);
        if(p == null) {
            return false;
        }
        if(!p.contains("*")) {
            return host.equals(p);
        }
        // Only "*.rest", with at least two labels in rest.
        if(!p.startsWith("*.") || p.indexOf('*', 1) >= 0) {
            return false;
        }
        final String rest = p.substring(1);    // ".example.com"
        if(rest.indexOf('.', 1) < 0) {
            return false;
        }
        if(!host.endsWith(rest)) {
            return false;
        }
        final String first = host.substring(0, host.length() - rest.length());
        return !first.isEmpty() && first.indexOf('.') < 0;
    }

    /* Four bytes for a dotted quad of decimal numbers 0 to 255, else null. */
    private static byte[] parseIPv4(String s) {
        final String[] parts = s.split("\\.", -1);
        if(parts.length != 4) {
            return null;
        }
        final byte[] out = new byte[4];
        for(int i = 0; i < 4; i++) {
            final String part = parts[i];
            if(part.isEmpty() || part.length() > 3) {
                return null;
            }
            int v = 0;
            for(int j = 0; j < part.length(); j++) {
                final char c = part.charAt(j);
                if(c < '0' || c > '9') {
                    return null;
                }
                v = v * 10 + (c - '0');
            }
            if(v > 255) {
                return null;
            }
            out[i] = (byte) v;
        }
        return out;
    }

    private static boolean isAscii(String s) {
        for(int i = 0; i < s.length(); i++) {
            if(s.charAt(i) > 0x7F) {
                return false;
            }
        }
        return true;
    }
}
