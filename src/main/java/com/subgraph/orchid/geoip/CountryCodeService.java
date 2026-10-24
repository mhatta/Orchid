package com.subgraph.orchid.geoip;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.Logger;

/**
 * Country codes of IPv4 addresses, for the {cc} entries of node filters
 * (ExcludeNodes, ExitNodes, ...) and for display.
 *
 * The database is Tor's "geoip" file: one "LOW,HIGH,CC" line per address
 * range, with the addresses as 32 bit integers, made by Tor from the IPFire
 * Location database (https://location.ipfire.org/, CC BY-SA 4.0).  Orchid
 * does not ship it; it uses the first of these that exists (a ".gz" file is
 * read too):
 *
 * <ol>
 * <li>the file named by the system property {@value #GEOIP_FILE_PROPERTY},</li>
 * <li><code>data/geoip</code> in the working directory (see
 *     <code>tools/update-geoip.sh</code>),</li>
 * <li>the file installed with Tor: <code>/usr/share/tor/geoip</code> (the
 *     tor-geoipdb package of Debian and Ubuntu),
 *     <code>/usr/local/share/tor/geoip</code> or
 *     <code>/opt/homebrew/share/tor/geoip</code>,</li>
 * <li>the classpath resource <code>/com/subgraph/orchid/geoip/geoip</code>,
 *     for applications that bundle it.</li>
 * </ol>
 *
 * Without a database every address has the country code {@value #UNKNOWN},
 * as addresses not in the database do.  The database is loaded on first use.
 */
public class CountryCodeService {
    private static final Logger logger = Logger.getInstance(CountryCodeService.class);

    /** System property naming the geoip file to use. */
    public static final String GEOIP_FILE_PROPERTY = "com.subgraph.orchid.geoipFile";

    /** The country code of addresses that are not in the database. */
    public static final String UNKNOWN = "??";

    private static final String[] DEFAULT_LOCATIONS = {
        "data/geoip",
        "/usr/share/tor/geoip",
        "/usr/local/share/tor/geoip",
        "/opt/homebrew/share/tor/geoip",
    };
    private static final String RESOURCE = "/com/subgraph/orchid/geoip/geoip";

    private static final Charset ASCII = Charset.forName("US-ASCII");

    private static class Holder {
        static final CountryCodeService INSTANCE = loadDefault();
    }

    public static CountryCodeService getInstance() {
        return Holder.INSTANCE;
    }

    /*
     * The ranges, sorted and not overlapping: rangeStart[i]..rangeEnd[i]
     * (unsigned) has the country code codes[codeIndex[i]].
     */
    private final int[] rangeStart;
    private final int[] rangeEnd;
    private final short[] codeIndex;
    private final String[] codes;
    private final String source;

    private CountryCodeService(int[] rangeStart, int[] rangeEnd, short[] codeIndex, String[] codes, String source) {
        this.rangeStart = rangeStart;
        this.rangeEnd = rangeEnd;
        this.codeIndex = codeIndex;
        this.codes = codes;
        this.source = source;
    }

    /** A service without a database: every address is {@value #UNKNOWN}. */
    static CountryCodeService empty() {
        return new CountryCodeService(new int[0], new int[0], new short[0], new String[0], null);
    }

    /**
     * Whether a database was found.  Without one, country codes in node
     * filters match no relay.
     */
    public boolean isAvailable() {
        return source != null;
    }

    /** Where the database was read from, or null. */
    public String getSource() {
        return source;
    }

    /** The number of address ranges with a known country. */
    public int getRangeCount() {
        return rangeStart.length;
    }

    public String getCountryCodeForAddress(IPv4Address address) {
        final int ip = address.getAddressData();
        int lo = 0;
        int hi = rangeStart.length - 1;
        while(lo <= hi) {
            final int mid = (lo + hi) >>> 1;
            if(compareUnsigned(ip, rangeStart[mid]) < 0) {
                hi = mid - 1;
            } else if(compareUnsigned(ip, rangeEnd[mid]) > 0) {
                lo = mid + 1;
            } else {
                return codes[codeIndex[mid]];
            }
        }
        return UNKNOWN;
    }

    private static int compareUnsigned(int a, int b) {
        return Integer.compare(a ^ Integer.MIN_VALUE, b ^ Integer.MIN_VALUE);
    }

    private static CountryCodeService loadDefault() {
        final String property = System.getProperty(GEOIP_FILE_PROPERTY);
        if(property != null && !property.isEmpty()) {
            final CountryCodeService s = tryLoadFile(new File(property));
            if(s != null) {
                return s;
            }
            logger.warn("Cannot read the geoip file '"+ property +"' named by "+ GEOIP_FILE_PROPERTY);
        }
        for(String location: DEFAULT_LOCATIONS) {
            CountryCodeService s = tryLoadFile(new File(location));
            if(s == null) {
                s = tryLoadFile(new File(location + ".gz"));
            }
            if(s != null) {
                return s;
            }
        }
        for(String resource: new String[] { RESOURCE, RESOURCE + ".gz" }) {
            final InputStream input = CountryCodeService.class.getResourceAsStream(resource);
            if(input != null) {
                final CountryCodeService s = tryLoad(input, resource.endsWith(".gz"), "classpath:"+ resource);
                if(s != null) {
                    return s;
                }
            }
        }
        logger.warn("No geoip database found, so the country codes of relays are unknown and "
                + "{cc} entries in node filters match no relay.  Install Tor's geoip file "
                + "(e.g. the tor-geoipdb package), run tools/update-geoip.sh, or set "
                + GEOIP_FILE_PROPERTY);
        return empty();
    }

    private static CountryCodeService tryLoadFile(File file) {
        if(!file.isFile() || !file.canRead()) {
            return null;
        }
        try {
            return tryLoad(new FileInputStream(file), file.getName().endsWith(".gz"), file.getPath());
        } catch (IOException e) {
            return null;
        }
    }

    private static CountryCodeService tryLoad(InputStream input, boolean gzip, String source) {
        try {
            final CountryCodeService s = load(gzip ? new GZIPInputStream(input) : input, source);
            logger.debug("Loaded "+ s.getRangeCount() +" geoip ranges from "+ source);
            return s;
        } catch (IOException e) {
            logger.warn("Error reading geoip database "+ source +": "+ e.getMessage());
            return null;
        } finally {
            try {
                input.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    /**
     * Read a database in Tor's geoip format.  Comments (#) and blank lines
     * are skipped; the ranges must be in ascending order, as Tor writes them.
     */
    static CountryCodeService load(InputStream input, String source) throws IOException {
        final BufferedReader reader = new BufferedReader(new InputStreamReader(input, ASCII));
        final List<String> codeList = new ArrayList<String>();
        final Map<String, Integer> codeIndexes = new HashMap<String, Integer>();
        int[] start = new int[1 << 16];
        int[] end = new int[1 << 16];
        short[] index = new short[1 << 16];
        int n = 0;
        long previousEnd = -1;
        int lineNumber = 0;
        String line;
        while((line = reader.readLine()) != null) {
            lineNumber++;
            line = line.trim();
            if(line.isEmpty() || line.charAt(0) == '#') {
                continue;
            }
            final String[] fields = line.split(",");
            if(fields.length != 3) {
                throw new IOException("line "+ lineNumber +": expected LOW,HIGH,CC");
            }
            final long low, high;
            try {
                low = Long.parseLong(fields[0].trim());
                high = Long.parseLong(fields[1].trim());
            } catch (NumberFormatException e) {
                throw new IOException("line "+ lineNumber +": bad address");
            }
            if(low < 0 || high > 0xFFFFFFFFL || low > high || low <= previousEnd) {
                throw new IOException("line "+ lineNumber +": bad or unordered range");
            }
            final String cc = fields[2].trim().toUpperCase(Locale.ROOT);
            if(cc.length() != 2) {
                throw new IOException("line "+ lineNumber +": bad country code '"+ cc +"'");
            }
            previousEnd = high;
            if(cc.equals(UNKNOWN)) {
                continue;
            }
            if(n == start.length) {
                start = Arrays.copyOf(start, n * 2);
                end = Arrays.copyOf(end, n * 2);
                index = Arrays.copyOf(index, n * 2);
            }
            Integer ci = codeIndexes.get(cc);
            if(ci == null) {
                ci = codeList.size();
                codeList.add(cc);
                codeIndexes.put(cc, ci);
            }
            start[n] = (int) low;
            end[n] = (int) high;
            index[n] = (short) ci.intValue();
            n++;
        }
        return new CountryCodeService(Arrays.copyOf(start, n), Arrays.copyOf(end, n), Arrays.copyOf(index, n),
                codeList.toArray(new String[0]), source);
    }
}
