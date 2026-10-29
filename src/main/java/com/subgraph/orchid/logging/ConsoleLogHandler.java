package com.subgraph.orchid.logging;

import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * The default {@link LogHandler}: one line per message on
 * <code>System.out</code>, as Orchid always logged.
 */
public class ConsoleLogHandler implements LogHandler {
    public static final ConsoleLogHandler INSTANCE = new ConsoleLogHandler();

    /* SimpleDateFormat is not thread safe: guarded by itself. */
    private final SimpleDateFormat timestampFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");

    public void log(SysLog level, String name, String message, Throwable throwable) {
        final String timestamp;
        synchronized(timestampFormat) {
            timestamp = timestampFormat.format(new Date());
        }
        final StringBuilder sb = new StringBuilder();
        sb.append(timestamp).append(' ').append(label(level)).append(" - ").append(name).append(" - ").append(message);
        if(throwable != null) {
            sb.append(": ").append(throwable);
        }
        final PrintStream out = System.out;
        out.println(sb);
    }

    static String label(SysLog level) {
        if(level.isGreaterOrEqual(SysLog.CRITICAL)) {
            return "FATAL";
        } else if(level.isGreaterOrEqual(SysLog.ERROR)) {
            return "ERROR";
        } else if(level.isGreaterOrEqual(SysLog.WARNING)) {
            return "WARN";
        } else if(level.isGreaterOrEqual(SysLog.INFORMATIONAL)) {
            return "INFO";
        } else {
            return "DEBUG";
        }
    }
}
