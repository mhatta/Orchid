package com.subgraph.orchid.socks;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import com.subgraph.orchid.ProxyStatistics;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.logging.Logger;

/**
 * What the SOCKS and HTTP tunnel ports share: their passwords
 * ({@link TorConfig#getSocksPassword()}, {@link TorConfig#getSocksPasswords()})
 * and the handling of requests that give only an address
 * ({@link TorConfig#getSafeSocks()}, {@link TorConfig#getWarnUnsafeSocks()}).
 */
final class ProxyAuthentication {
    private static final Logger logger = Logger.getInstance(ProxyAuthentication.class);
    private static final Charset UTF8 = Charset.forName("UTF-8");

    private ProxyAuthentication() {}

    /** Whether clients must give a password. */
    static boolean isRequired(TorConfig config) {
        return config.getSocksPassword() != null || !config.getSocksPasswords().isEmpty();
    }

    /**
     * The profile whose password this is: {@link ProxyStatistics#NO_PROFILE}
     * for {@link TorConfig#getSocksPassword()}, the name of a profile of
     * {@link TorConfig#getSocksPasswords()}, or null if it is none of them.
     * Every password is compared (in constant time), so that the time taken
     * does not say which one matched.
     */
    static String profileFor(TorConfig config, byte[] password) {
        String found = null;
        final String single = config.getSocksPassword();
        if(single != null && MessageDigest.isEqual(password, single.getBytes(UTF8))) {
            found = ProxyStatistics.NO_PROFILE;
        }
        for(Map.Entry<String, String> e: config.getSocksPasswords().entrySet()) {
            if(MessageDigest.isEqual(password, e.getValue().getBytes(UTF8)) && found == null) {
                found = e.getKey();
            }
        }
        return found;
    }

    /**
     * The profile of a client that gave this password, or null if the
     * port must refuse it: with no password required, a password that is
     * not a profile's is accepted without a profile.
     */
    static String authenticate(TorConfig config, byte[] password) {
        final String profile = (password == null) ? null : profileFor(config, password);
        if(profile != null) {
            return profile;
        }
        return isRequired(config) ? null : ProxyStatistics.NO_PROFILE;
    }

    private static final Pattern IPV4_LITERAL = Pattern.compile("[0-9]{1,3}(\\.[0-9]{1,3}){3}");

    /**
     * Whether a host name is an address literal: a dotted-quad IPv4
     * address, or an IPv6 address (with or without brackets).  A client
     * that sends one has most likely looked the name up itself.
     */
    static boolean isAddressLiteral(String host) {
        if(host == null) {
            return false;
        }
        final String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        return h.indexOf(':') >= 0 || IPV4_LITERAL.matcher(h).matches();
    }

    private static final long WARNING_INTERVAL_MS = 5000;
    private static final AtomicLong lastWarning = new AtomicLong(Long.MIN_VALUE / 2);

    /**
     * A request gave only an address: warn (at most every five seconds, for
     * the whole process) if WarnUnsafeSocks or SafeSocks is on, and say
     * whether SafeSocks refuses it.
     */
    static boolean refuseAddressOnly(TorConfig config) {
        final boolean refuse = config.getSafeSocks();
        if(config.getWarnUnsafeSocks() || refuse) {
            final long now = System.currentTimeMillis();
            final long last = lastWarning.get();
            if(now - last >= WARNING_INTERVAL_MS && lastWarning.compareAndSet(last, now)) {
                logger.warn("An application gave only an IP address, not a host name: it has most likely "+
                        "looked the name up itself, outside Tor, so that its network saw which host it went to. "+
                        "Applications should send host names (SOCKS 5 with a name, SOCKS 4a, or HTTP CONNECT)."+
                        (refuse ? "  SafeSocks is on: the request was refused." : ""));
            }
        }
        return refuse;
    }
}
