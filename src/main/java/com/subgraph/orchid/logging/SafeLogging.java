package com.subgraph.orchid.logging;

import java.util.regex.Pattern;

import com.subgraph.orchid.BridgeRouter;
import com.subgraph.orchid.Router;

/**
 * Whether log messages may name the destinations of streams (Tor's
 * SafeLogging option), and the addresses of the relays and bridges Orchid
 * connects to.  On by default.  It follows
 * {@link com.subgraph.orchid.TorConfig#setSafeLogging(boolean)}; as the
 * logger, it is shared by all Tor clients in the process.
 *
 * <p>A client connects only to its guards, its bridges and directory
 * servers, so the address of a relay in a connection message says which
 * guard or bridge this client uses: something that identifies it for
 * months.  With SafeLogging on, messages name relays by nickname only and
 * bridges not at all, and the IP addresses in error messages (from the
 * socket layer, which on Android also names the device's own address) are
 * scrubbed.
 */
public final class SafeLogging {
    public static final String SCRUBBED = "[scrubbed]";

    /*
     * Dotted-quad IPv4 addresses; IPv6 addresses in full (eight groups) or
     * compressed ("::") form, with an optional zone.  Times such as
     * "10:00:00" have neither form and are left alone.
     */
    private static final String H = "[0-9A-Fa-f]{1,4}";
    private static final Pattern IPV4 = Pattern.compile("(?<![0-9.])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![0-9.])");
    private static final Pattern IPV6 = Pattern.compile("(?<![0-9A-Za-z:])"
            + "(?:(?:"+ H +":){7}"+ H +"|(?:"+ H +"(?::"+ H +")*)?::(?:"+ H +"(?::"+ H +")*)?)"
            + "(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])");

    private static volatile boolean enabled = true;

    private SafeLogging() {}

    public static boolean isEnabled() {
        return enabled;
    }

    public static void setEnabled(boolean value) {
        enabled = value;
    }

    /** "host:port", or "[scrubbed]:port" when SafeLogging is on. */
    public static String target(String host, int port) {
        return (enabled ? SCRUBBED : host) + ":"+ port;
    }

    /**
     * How to name a relay in a log or error message: its nickname, or
     * "[Bridge]" for a bridge when SafeLogging is on (a bridge has no
     * nickname, and its address is meant to stay secret).
     *
     * @since 2.8.1
     */
    public static String relay(Router router) {
        if(router == null) {
            return "(none)";
        }
        if(enabled && router instanceof BridgeRouter) {
            return "[Bridge]";
        }
        return router.getNickname();
    }

    /**
     * The message with its IPv4 and IPv6 addresses replaced by
     * "[scrubbed]" when SafeLogging is on, unchanged otherwise.
     *
     * @since 2.8.1
     */
    public static String addresses(String message) {
        if(!enabled || message == null) {
            return message;
        }
        final String noV4 = IPV4.matcher(message).replaceAll(SCRUBBED);
        return IPV6.matcher(noV4).replaceAll(SCRUBBED);
    }
}
