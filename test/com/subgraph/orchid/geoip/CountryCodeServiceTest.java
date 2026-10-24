package com.subgraph.orchid.geoip;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.junit.Test;

import com.subgraph.orchid.data.IPv4Address;

/*
 * Lookups in a database in Tor's geoip format.  The ranges are made up for
 * the test; the real database is not part of Orchid.
 */
public class CountryCodeServiceTest {
	private static final String DB =
			"# A comment\n" +
			"\n" +
			"16777216,16777471,AU\n" +          // 1.0.0.0 - 1.0.0.255
			"16777472,16778239,cn\n" +          // 1.0.1.0 - 1.0.3.255
			"16778240,16779263,??\n" +          // 1.0.4.0 - 1.0.7.255
			"3232235520,3232301055,JP\n" +      // 192.168.0.0 - 192.168.255.255
			"4294967040,4294967295,FR\n";       // 255.255.255.0 - 255.255.255.255

	private static CountryCodeService load(String text) throws IOException {
		return CountryCodeService.load(new ByteArrayInputStream(text.getBytes(Charset.forName("US-ASCII"))), "test");
	}

	private static String cc(CountryCodeService s, String address) {
		return s.getCountryCodeForAddress(IPv4Address.createFromString(address));
	}

	@Test
	public void testLookup() throws IOException {
		final CountryCodeService s = load(DB);
		assertTrue(s.isAvailable());
		assertEquals(4, s.getRangeCount());
		assertEquals("AU", cc(s, "1.0.0.0"));
		assertEquals("AU", cc(s, "1.0.0.255"));
		assertEquals("CN", cc(s, "1.0.1.0"));
		assertEquals("CN", cc(s, "1.0.3.255"));
		assertEquals("JP", cc(s, "192.168.10.1"));
		// addresses with the top bit set compare as unsigned
		assertEquals("FR", cc(s, "255.255.255.255"));
		assertEquals("FR", cc(s, "255.255.255.0"));
	}

	@Test
	public void testUnknown() throws IOException {
		final CountryCodeService s = load(DB);
		assertEquals(CountryCodeService.UNKNOWN, cc(s, "0.255.255.255"));
		assertEquals(CountryCodeService.UNKNOWN, cc(s, "1.0.5.1"));          // listed as ??
		assertEquals(CountryCodeService.UNKNOWN, cc(s, "10.0.0.1"));         // not listed
		assertEquals(CountryCodeService.UNKNOWN, cc(s, "255.255.254.255"));
	}

	@Test
	public void testEmpty() {
		final CountryCodeService s = CountryCodeService.empty();
		assertFalse(s.isAvailable());
		assertEquals(CountryCodeService.UNKNOWN, cc(s, "1.0.0.1"));
	}

	@Test
	public void testMalformed() {
		for(String bad: new String[] { "1,2\n", "x,2,US\n", "5,4,US\n", "1,2,USA\n",
				"10,20,US\n15,30,DE\n", "0,4294967296,US\n" }) {
			try {
				load(bad);
				fail(bad);
			} catch (IOException e) {
				// expected
			}
		}
	}
}
