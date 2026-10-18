package com.subgraph.orchid.directory.consensus;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.junit.Test;

import com.subgraph.orchid.ConsensusDocument;
import com.subgraph.orchid.RouterStatus;
import com.subgraph.orchid.directory.DocumentFieldParserImpl;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.encoders.Base64;

/**
 * Parses a microdesc consensus written in the format served by the current
 * Tor network (dir-spec section 3.4.1), including items Orchid did not know
 * about when it was written: parameters whose names contain '-',
 * shared random values, protocol lines, "pr" and "a" lines in router entries,
 * "Unmeasured=1" bandwidth entries and sha256 directory signatures.
 */
public class ConsensusDocumentParserTest {
	private static final Charset ASCII = Charset.forName("ISO-8859-1");

	private static String b64NoPad(byte[] data) {
		String s = new String(Base64.encode(data), ASCII);
		while(s.endsWith("=")) {
			s = s.substring(0, s.length() - 1);
		}
		return s;
	}

	private static byte[] filled(int len, int value) {
		final byte[] b = new byte[len];
		Arrays.fill(b, (byte) value);
		return b;
	}

	static String consensus(String paramsLine) {
		final StringBuilder sb = new StringBuilder();
		sb.append("network-status-version 3 microdesc\n");
		sb.append("vote-status consensus\n");
		sb.append("consensus-method 34\n");
		sb.append("valid-after 2026-10-18 03:00:00\n");
		sb.append("fresh-until 2026-10-18 04:00:00\n");
		sb.append("valid-until 2026-10-18 06:00:00\n");
		sb.append("voting-delay 300 300\n");
		sb.append("client-versions 0.4.8.17,0.4.8.18,0.4.9.3-alpha\n");
		sb.append("server-versions 0.4.8.17,0.4.8.18,0.4.9.3-alpha\n");
		sb.append("known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid\n");
		sb.append("recommended-client-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2\n");
		sb.append("recommended-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2\n");
		sb.append("required-client-protocols Cons=2 Desc=2 Link=4 Microdesc=2 Relay=2\n");
		sb.append("required-relay-protocols Cons=2 Desc=2 DirCache=2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2\n");
		sb.append(paramsLine).append('\n');
		sb.append("shared-rand-previous-value 9 ").append(new String(Base64.encode(filled(32, 0x11)), ASCII)).append('\n');
		sb.append("shared-rand-current-value 9 ").append(new String(Base64.encode(filled(32, 0x22)), ASCII)).append('\n');
		sb.append("dir-source moria1 F533C81CEF0BC0267857C99B2F471ADF249FA232 128.31.0.39 128.31.0.39 9231 9201\n");
		sb.append("contact 1024D/EB5A896A28988BF5 arma mit edu\n");
		sb.append("vote-digest 0123456789ABCDEF0123456789ABCDEF01234567\n");
		sb.append("r ExampleRelay ").append(b64NoPad(filled(20, 0x33))).append(" 2026-10-18 01:23:45 192.0.2.1 9001 0\n");
		sb.append("a [2001:db8::1]:9001\n");
		sb.append("m ").append(b64NoPad(filled(32, 0x44))).append('\n');
		sb.append("s Fast Guard HSDir Running Stable V2Dir Valid\n");
		sb.append("v Tor 0.4.8.18\n");
		sb.append("pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n");
		sb.append("w Bandwidth=1234 Unmeasured=1\n");
		sb.append("directory-footer\n");
		sb.append("bandwidth-weights Wbd=0 Wbe=0 Wbg=4142 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5858 Wgm=5858 Wmb=10000 Wmd=0 Wme=0 Wmg=4142 Wmm=10000\n");
		sb.append("directory-signature sha256 F533C81CEF0BC0267857C99B2F471ADF249FA232 0123456789ABCDEF0123456789ABCDEF01234567\n");
		sb.append("-----BEGIN SIGNATURE-----\n");
		sb.append(new String(Base64.encode(filled(128, 0x55)), ASCII)).append('\n');
		sb.append("-----END SIGNATURE-----\n");
		return sb.toString();
	}

	static BasicDocumentParsingResult<ConsensusDocument> parse(String document) {
		final ByteBuffer buffer = ByteBuffer.wrap(document.getBytes(ASCII));
		final ConsensusDocumentParser parser = new ConsensusDocumentParser(new DocumentFieldParserImpl(buffer));
		final BasicDocumentParsingResult<ConsensusDocument> result = new BasicDocumentParsingResult<ConsensusDocument>();
		parser.parse(result);
		return result;
	}

	@Test
	public void testParsesCurrentConsensusFormat() {
		final String params = "params AuthDirMaxServersPerAddr=8 CircuitPriorityHalflifeMsec=30000 cc_alg=2 "
				+ "guard-n-primary-dir-guards-to-use=2 guard-n-primary-guards-to-use=2 hsdir_interval=1440 "
				+ "hsdir_spread_store=4 overload_dns_timeout_scale_percent=1000 sendme_emit_min_version=1";
		final BasicDocumentParsingResult<ConsensusDocument> result = parse(consensus(params));
		assertTrue("parse failed: "+ result.getMessage(), result.isOkay());
		final ConsensusDocument doc = result.getDocument();
		assertNotNull(doc);
		assertEquals(ConsensusDocument.ConsensusFlavor.MICRODESC, doc.getFlavor());
		assertEquals(2, doc.getIntegerParameter("guard-n-primary-dir-guards-to-use", 0, 0, 100));
		assertEquals(2, doc.getIntegerParameter("cc_alg", 0, 0, 100));
		assertEquals(1440, doc.getHSDirIntervalParameter());
		assertArrayEquals(filled(32, 0x11), doc.getSharedRandomPreviousValue());
		assertArrayEquals(filled(32, 0x22), doc.getSharedRandomCurrentValue());
		assertEquals(1, doc.getRouterStatusEntries().size());
		final RouterStatus rs = doc.getRouterStatusEntries().get(0);
		assertEquals("ExampleRelay", rs.getNickname());
		assertTrue(rs.hasFlag("HSDir"));
		assertEquals(10000, doc.getBandwidthWeight("Wbm"));
	}

	@Test
	public void testMalformedParameterIsSkipped() {
		final BasicDocumentParsingResult<ConsensusDocument> result = parse(consensus("params bad=notanumber cc_alg=2 also*bad=1 weird"));
		assertTrue("parse failed: "+ result.getMessage(), result.isOkay());
		final ConsensusDocument doc = result.getDocument();
		assertEquals(2, doc.getIntegerParameter("cc_alg", 0, 0, 100));
		assertEquals(-1, doc.getIntegerParameter("bad", -1, -1, 100));
	}

	@Test
	public void testNegativeParameterValue() {
		final BasicDocumentParsingResult<ConsensusDocument> result = parse(consensus("params some-param=-5"));
		assertTrue("parse failed: "+ result.getMessage(), result.isOkay());
		assertEquals(-5, result.getDocument().getIntegerParameter("some-param", 0, -10, 10));
	}
}
