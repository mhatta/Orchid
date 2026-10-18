package com.subgraph.orchid.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import com.subgraph.orchid.DirectoryServer;
import com.subgraph.orchid.data.HexDigest;

/**
 * Checks the built-in directory authority list against reference values
 * (written without spaces, as in Tor's auth_dirs.inc and Arti's
 * tor-dircommon), so that a typo in the spaced fingerprints is caught.
 */
public class TrustedAuthoritiesTest {

	/* nickname, v3ident, RSA identity fingerprint, IPv4 address, orport, dirport */
	private static final String[][] EXPECTED = {
		{ "moria1",     "F533C81CEF0BC0267857C99B2F471ADF249FA232", "1A25C6358DB91342AA51720A5038B72742732498", "128.31.0.39",    "9201", "9231" },
		{ "tor26",      "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", "FAA4BCA4A6AC0FB4CA2F8AD5A11D9E122BA894F6", "217.196.147.77", "443",  "80" },
		{ "dizum",      "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", "7EA6EAD6FD83083C538F44038BBFA077587DD755", "45.66.35.11",    "443",  "80" },
		{ "gabelmoo",   "ED03BB616EB2F60BEC80151114BB25CEF515B226", "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281", "131.188.40.189", "443",  "80" },
		{ "dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", "7BE683E65D48141321C5ED92F075C55364AC7123", "193.23.244.244", "443",  "80" },
		{ "maatuska",   "49015F787433103580E3B66A1707A00E60F2D15B", "BD6A829255CB08E66FBE7D3748363586E46B3810", "171.25.193.9",   "80",   "443" },
		{ "longclaw",   "23D15D965BC35114467363C165C4F724B64B4F66", "74A910646BCEEFBCD2E874FC1DC997430F968145", "199.58.81.140",  "443",  "80" },
		{ "bastet",     "27102BC123E7AF1D4741AE047E160C91ADC76B21", "24E2F139121D4394C54B5BCC368B3B411857C413", "204.13.164.118", "443",  "80" },
		{ "faravahar",  "70849B868D606BAECFB6128C5E3D782029AA394F", "E3E42D35F801C9D5AB23584E0025D56FE2B33396", "216.218.219.41", "443",  "80" },
	};

	private static DirectoryServer findByNickname(String nickname) {
		for(DirectoryServer ds: TrustedAuthorities.getInstance().getAuthorityServers()) {
			if(nickname.equals(ds.getNickname())) {
				return ds;
			}
		}
		return null;
	}

	@Test
	public void testV3AuthorityCount() {
		assertEquals(EXPECTED.length, TrustedAuthorities.getInstance().getV3AuthorityServerCount());
	}

	@Test
	public void testAuthorityEntries() {
		for(String[] e: EXPECTED) {
			final DirectoryServer ds = findByNickname(e[0]);
			assertNotNull("missing authority "+ e[0], ds);
			assertEquals(e[0] + " v3ident", HexDigest.createFromString(e[1]), ds.getV3Identity());
			assertEquals(e[0] + " fingerprint", HexDigest.createFromString(e[2]), ds.getIdentityHash());
			assertEquals(e[0] + " address", e[3], ds.getAddress().toString());
			assertEquals(e[0] + " orport", Integer.parseInt(e[4]), ds.getOnionPort());
			assertEquals(e[0] + " dirport", Integer.parseInt(e[5]), ds.getDirectoryPort());
			assertEquals(ds, TrustedAuthorities.getInstance().getAuthorityServerByIdentity(HexDigest.createFromString(e[1])));
		}
	}

	@Test
	public void testRetiredKeysAreGone() {
		/* old moria1, tor26 and Faravahar v3 identities */
		assertNull(TrustedAuthorities.getInstance().getAuthorityServerByIdentity(HexDigest.createFromString("D586D18309DED4CD6D57C18FDB97EFA96D330566")));
		assertNull(TrustedAuthorities.getInstance().getAuthorityServerByIdentity(HexDigest.createFromString("14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4")));
		assertNull(TrustedAuthorities.getInstance().getAuthorityServerByIdentity(HexDigest.createFromString("EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97")));
	}
}
