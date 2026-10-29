package com.subgraph.orchid.logging;

/**
 * Whether log messages may name the destinations of streams (Tor's
 * SafeLogging option).  On by default.  It follows
 * {@link com.subgraph.orchid.TorConfig#setSafeLogging(boolean)}; as the
 * logger, it is shared by all Tor clients in the process.
 */
public final class SafeLogging {
    public static final String SCRUBBED = "[scrubbed]";

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
}
