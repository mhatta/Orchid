package com.subgraph.orchid.directory.router;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.directory.DocumentFieldParserImpl;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.encoders.Hex;

/**
 * Microdescriptors in the format produced by current consensus methods:
 * no TAP key object after "onion-key", "id ed25519" / "id rsa1024" lines,
 * items unknown to Orchid ("family-ids", "p6"), and extra trailing
 * arguments, which dir-spec requires parsers to accept.
 */
public class RouterMicrodescriptorParserTest {
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

	static String microdescriptor(int seed, String ntorExtra) {
		return "onion-key\n"
				+ "ntor-onion-key " + b64NoPad(filled(32, seed)) + ntorExtra + "\n"
				+ "family-ids ed25519:" + b64NoPad(filled(32, seed + 1)) + "\n"
				+ "p accept 80,443\n"
				+ "p6 accept 80,443\n"
				+ "id rsa1024 " + b64NoPad(filled(20, seed + 2)) + "\n"
				+ "id ed25519 " + b64NoPad(filled(32, seed + 3)) + "\n";
	}

	static List<RouterMicrodescriptor> parse(String text) {
		final ByteBuffer buffer = ByteBuffer.wrap(text.getBytes(ASCII));
		final RouterMicrodescriptorParser parser = new RouterMicrodescriptorParser(new DocumentFieldParserImpl(buffer));
		final BasicDocumentParsingResult<RouterMicrodescriptor> result = new BasicDocumentParsingResult<RouterMicrodescriptor>();
		parser.parse(result);
		assertTrue("parse failed: "+ result.getMessage(), result.isOkay());
		return result.getParsedDocuments();
	}

	static String sha256Hex(String s) throws Exception {
		return new String(Hex.encode(MessageDigest.getInstance("SHA-256").digest(s.getBytes(ASCII))));
	}

	@Test
	public void testTapLessMicrodescriptorsAndDigests() throws Exception {
		final String md1 = microdescriptor(0x10, "");
		final String md2 = microdescriptor(0x20, "");
		final List<RouterMicrodescriptor> mds = parse(md1 + md2);
		assertEquals(2, mds.size());

		final RouterMicrodescriptorImpl first = (RouterMicrodescriptorImpl) mds.get(0);
		assertNull(first.getOnionKey());
		assertArrayEquals(filled(32, 0x10), first.getNTorOnionKey());
		assertArrayEquals(filled(32, 0x13), first.getEd25519Identity());
		assertTrue(first.exitPolicyAccepts(443));
		/* The digest must cover exactly the text of each microdescriptor, as the consensus "m" line does. */
		assertEquals(sha256Hex(md1), first.getDescriptorDigest().toString());
		assertEquals(sha256Hex(md2), mds.get(1).getDescriptorDigest().toString());
	}

	@Test
	public void testExtraArgumentsAreAccepted() {
		final List<RouterMicrodescriptor> mds = parse(microdescriptor(0x30, " some future argument"));
		assertEquals(1, mds.size());
		assertArrayEquals(filled(32, 0x30), mds.get(0).getNTorOnionKey());
	}
}
