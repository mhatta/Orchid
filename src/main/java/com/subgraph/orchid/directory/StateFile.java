package com.subgraph.orchid.directory;

import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import com.subgraph.orchid.DirectoryStore;
import com.subgraph.orchid.DirectoryStore.CacheFile;
import com.subgraph.orchid.Tor;
import com.subgraph.orchid.logging.Logger;

/**
 * The "state" file: the sampled entry guards, one line each, in the format
 * of Tor's state file (guard-spec, appendix "Persistent state format"):
 *
 * <pre>
 * Guard in=default rsa_id=&lt;hex&gt; nickname=&lt;name&gt; sampled_on=2026-11-09T03:12:45 sampled_by=Orchid-2.6.0 listed=1 confirmed_on=... confirmed_idx=0
 * </pre>
 *
 * The meaning of the fields belongs to EntryGuards; this class only keeps
 * them, in order and with fields it does not know, as the spec asks.
 * Lines with other keywords are kept as they are.
 *
 * Files written by Orchid before 2.6 hold the guards in Tor's old format
 * (EntryGuard, EntryGuardAddedBy, EntryGuardDownSince,
 * EntryGuardUnlistedSince).  Those guards are read as sampled guards that
 * are confirmed in the order of the file, so that a client keeps the guards
 * it has been using; the next write uses the new format.
 */
public class StateFile {
    private static final Logger logger = Logger.getInstance(StateFile.class);

    final static String KEYWORD_GUARD = "Guard";
    final static String KEYWORD_ENTRY_GUARD = "EntryGuard";
    final static String KEYWORD_ENTRY_GUARD_ADDED_BY = "EntryGuardAddedBy";
    final static String KEYWORD_ENTRY_GUARD_DOWN_SINCE = "EntryGuardDownSince";
    final static String KEYWORD_ENTRY_GUARD_UNLISTED_SINCE = "EntryGuardUnlistedSince";

    private final DirectoryStore directoryStore;

    /* Guard entries in file order; and every other line, kept as read. */
    private final List<Map<String, String>> guards = new ArrayList<Map<String, String>>();
    private final List<String> otherLines = new ArrayList<String>();

    StateFile(DirectoryStore store) {
        this.directoryStore = store;
    }

    /** ISO 8601 in UTC without spaces, as Tor writes dates in the state file. */
    public static String formatDate(Date date) {
        return isoFormat().format(date);
    }

    /** null if s is not a date written by formatDate(). */
    public static Date parseDate(String s) {
        if(s == null) {
            return null;
        }
        try {
            return isoFormat().parse(s);
        } catch (ParseException e) {
            return null;
        }
    }

    private static DateFormat isoFormat() {
        final SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        f.setLenient(false);
        return f;
    }

    /** A copy of the guard entries, in file order. */
    public List<Map<String, String>> getGuards() {
        synchronized (guards) {
            final List<Map<String, String>> copy = new ArrayList<Map<String, String>>();
            for(Map<String, String> g: guards) {
                copy.add(new LinkedHashMap<String, String>(g));
            }
            return copy;
        }
    }

    /** Replace the guard entries and write the file. */
    public void setGuards(List<Map<String, String>> newGuards) {
        synchronized (guards) {
            guards.clear();
            for(Map<String, String> g: newGuards) {
                guards.add(new LinkedHashMap<String, String>(g));
            }
            writeFile();
        }
    }

    void writeFile() {
        directoryStore.writeData(CacheFile.STATE, getFileContents());
    }

    ByteBuffer getFileContents() {
        final StringBuilder sb = new StringBuilder();
        synchronized (guards) {
            for(String line: otherLines) {
                sb.append(line).append('\n');
            }
            for(Map<String, String> g: guards) {
                sb.append(KEYWORD_GUARD);
                for(Map.Entry<String, String> e: g.entrySet()) {
                    sb.append(' ').append(e.getKey()).append('=').append(e.getValue());
                }
                sb.append('\n');
            }
        }
        return ByteBuffer.wrap(sb.toString().getBytes(Tor.getDefaultCharset()));
    }

    void parseBuffer(ByteBuffer buffer) {
        synchronized (guards) {
            guards.clear();
            otherLines.clear();
            final List<String> lines = readLines(buffer);
            final LegacyReader legacy = new LegacyReader();
            for(String line: lines) {
                final String trimmed = line.trim();
                if(trimmed.isEmpty()) {
                    continue;
                }
                final String keyword = firstToken(trimmed);
                if(keyword.equals(KEYWORD_GUARD)) {
                    final Map<String, String> g = parseGuardLine(trimmed.substring(keyword.length()));
                    if(g != null) {
                        guards.add(g);
                    }
                } else if(legacy.accepts(keyword)) {
                    legacy.line(keyword, trimmed.substring(keyword.length()).trim());
                } else {
                    otherLines.add(line);
                }
            }
            if(guards.isEmpty()) {
                guards.addAll(legacy.finish());
            } else if(!legacy.finish().isEmpty()) {
                logger.info("State file has guards in both the new and the old format; using the new");
            }
        }
    }

    private static Map<String, String> parseGuardLine(String rest) {
        final Map<String, String> g = new LinkedHashMap<String, String>();
        for(String token: rest.trim().split("\\s+")) {
            final int eq = token.indexOf('=');
            if(eq <= 0) {
                continue;
            }
            g.put(token.substring(0, eq), token.substring(eq + 1));
        }
        if(!g.containsKey("rsa_id") || !g.containsKey("sampled_on")) {
            logger.warn("Ignoring a Guard line without rsa_id or sampled_on in the state file");
            return null;
        }
        return g;
    }

    private static String firstToken(String s) {
        final String[] parts = s.split("\\s+", 2);
        return parts[0];
    }

    private static List<String> readLines(ByteBuffer buffer) {
        final List<String> lines = new ArrayList<String>();
        if(buffer == null) {
            return lines;
        }
        final StringBuilder sb = new StringBuilder();
        while(buffer.hasRemaining()) {
            final char c = (char) (buffer.get() & 0xFF);
            if(c == '\n') {
                lines.add(sb.toString());
                sb.setLength(0);
            } else if(c != '\r') {
                sb.append(c);
            }
        }
        if(sb.length() > 0) {
            lines.add(sb.toString());
        }
        return lines;
    }

    /*
     * Reads the EntryGuard blocks of Orchid before 2.6 (and of Tor before
     * 0.3.0), whose dates were "yyyy-MM-dd HH:mm:ss" in local time.
     */
    private static class LegacyReader {
        private final List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        private Map<String, String> current;

        boolean accepts(String keyword) {
            return keyword.equals(KEYWORD_ENTRY_GUARD) || keyword.equals(KEYWORD_ENTRY_GUARD_ADDED_BY)
                    || keyword.equals(KEYWORD_ENTRY_GUARD_DOWN_SINCE) || keyword.equals(KEYWORD_ENTRY_GUARD_UNLISTED_SINCE);
        }

        void line(String keyword, String rest) {
            final String[] f = rest.isEmpty() ? new String[0] : rest.split("\\s+");
            if(keyword.equals(KEYWORD_ENTRY_GUARD)) {
                close();
                if(f.length < 2) {
                    logger.warn("Ignoring a malformed EntryGuard line in the state file");
                    return;
                }
                current = new LinkedHashMap<String, String>();
                current.put("in", "default");
                current.put("rsa_id", f[1]);
                current.put("nickname", f[0]);
                current.put("listed", "1");
            } else if(current == null) {
                return;
            } else if(keyword.equals(KEYWORD_ENTRY_GUARD_ADDED_BY) && f.length >= 4) {
                final Date added = parseLegacyDate(f[2] +" "+ f[3]);
                if(added != null) {
                    current.put("sampled_on", formatDate(added));
                    current.put("sampled_by", f[1]);
                }
            } else if(keyword.equals(KEYWORD_ENTRY_GUARD_UNLISTED_SINCE) && f.length >= 2) {
                final Date unlisted = parseLegacyDate(f[0] +" "+ f[1]);
                if(unlisted != null) {
                    current.put("listed", "0");
                    current.put("unlisted_since", formatDate(unlisted));
                }
            }
            /* EntryGuardDownSince is reachability, which guard-spec does not keep across runs. */
        }

        private void close() {
            if(current != null && current.containsKey("sampled_on")) {
                /*
                 * These guards were in use: they are confirmed, in file order.
                 * Confirmed now, not when sampled, so that a guard sampled
                 * long ago is kept for GUARD_CONFIRMED_MIN_LIFETIME instead
                 * of being dropped at the first start of the new version.
                 */
                current.put("confirmed_on", formatDate(new Date()));
                current.put("confirmed_idx", Integer.toString(result.size()));
                result.add(current);
            } else if(current != null) {
                logger.warn("Ignoring an EntryGuard without EntryGuardAddedBy in the state file");
            }
            current = null;
        }

        List<Map<String, String>> finish() {
            close();
            return result;
        }

        private static Date parseLegacyDate(String s) {
            try {
                final SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                f.setLenient(false);
                return f.parse(s);
            } catch (ParseException e) {
                return null;
            }
        }
    }
}
