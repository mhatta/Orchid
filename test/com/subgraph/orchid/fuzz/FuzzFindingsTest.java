package com.subgraph.orchid.fuzz;

import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;

import org.junit.Test;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.connections.CertsCellFuzzer;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

/*
 * The inputs that the first fuzzing runs found, reduced by hand: each used
 * to end in a runtime exception that the parsers did not catch.  The
 * targets catch the ways of refusing input, so passing means "refused".
 */
public class FuzzFindingsTest {

	private static byte[] readSeed(String path) {
		try {
			return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("test/fuzz/corpus", path));
		} catch (java.io.IOException e) {
			throw new AssertionError(e);
		}
	}

	private static byte[] ascii(String s) {
		return s.getBytes(StandardCharsets.ISO_8859_1);
	}

	@Test
	public void badBase64InMicrodescriptor() {
		MicrodescriptorFuzzer.fuzzerTestOneInput(ascii("onion-key\nntor-onion-key !!!!\n"));
		MicrodescriptorFuzzer.fuzzerTestOneInput(ascii("onion-key\nid ed25519 \u00ff\u00ff\u00ff\u00ff\n"));
	}

	@Test
	public void badHexInConsensusSignature() {
		final String consensus = new String(readSeed("consensus/seed-params"), StandardCharsets.ISO_8859_1);
		final int footer = consensus.indexOf("directory-footer");
		ConsensusFuzzer.fuzzerTestOneInput(ascii(consensus.substring(0, footer)
				+ "directory-footer\ndirectory-signature ZZZZ000000000000000000000000000000000000 0000\n"));
	}

	@Test
	public void objectHeaderWithoutKeywordOrAtEnd() {
		KeyCertificateFuzzer.fuzzerTestOneInput(ascii("dir-key-certificate-version 3\ndir-identity-key\n-----BEGIN-----\n"));
		KeyCertificateFuzzer.fuzzerTestOneInput(ascii("dir-key-certificate-version 3\ndir-identity-key\n"));
	}

	@Test
	public void fiveOctetAddressInKeyCertificate() {
		KeyCertificateFuzzer.fuzzerTestOneInput(ascii("dir-key-certificate-version 3\ndir-address 1.2.3.4.5:80\n"));
	}

	@Test
	public void routerDescriptorWithoutSigningKey() {
		RouterDescriptorFuzzer.fuzzerTestOneInput(ascii("router r 192.0.2.1 9001 0 0\n"
				+ "router-signature\n-----BEGIN SIGNATURE-----\nAAAA\n-----END SIGNATURE-----\n"));
	}

	@Test
	public void badExitPolicyAndHistoryInRouterDescriptor() {
		RouterDescriptorFuzzer.fuzzerTestOneInput(ascii("router r 192.0.2.1 9001 0 0\nreject /:80\n"));
		RouterDescriptorFuzzer.fuzzerTestOneInput(ascii("router r 192.0.2.1 9001 0 0\n"
				+ "read-history 2026-11-18 12:00:00 ( s) 1,2,3\n"));
	}

	@Test
	public void emptyCertsCell() {
		CertsCellFuzzer.fuzzerTestOneInput(new byte[0]);
	}

	@Test
	public void decodersRefuseWithTorParsingException() {
		try {
			HexDigest.createFromString("not hex");
			fail();
		} catch(TorParsingException e) {
			// expected
		}
		try {
			IPv4Address.createFromString("1.2.3.4.5");
			fail();
		} catch(TorParsingException e) {
			// expected
		}
	}
}
