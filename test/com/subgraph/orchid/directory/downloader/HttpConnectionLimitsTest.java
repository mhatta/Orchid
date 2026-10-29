package com.subgraph.orchid.directory.downloader;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.zip.Deflater;

import org.junit.Test;

import com.subgraph.orchid.Circuit;
import com.subgraph.orchid.CircuitNode;
import com.subgraph.orchid.Stream;

/**
 * A directory server cannot make Orchid read more than the limits allow.
 */
public class HttpConnectionLimitsTest {
	private static final Charset ASCII = Charset.forName("US-ASCII");

	private static HttpConnection connection(byte[] response, int maxBody) {
		final CircuitNode node = createNiceMock(CircuitNode.class);
		replay(node);
		final Circuit circuit = createNiceMock(Circuit.class);
		expect(circuit.getFinalCircuitNode()).andStubReturn(node);
		replay(circuit);
		final Stream stream = createNiceMock(Stream.class);
		expect(stream.getInputStream()).andStubReturn(new ByteArrayInputStream(response));
		expect(stream.getOutputStream()).andStubReturn(new ByteArrayOutputStream());
		expect(stream.getCircuit()).andStubReturn(circuit);
		replay(stream);
		return new HttpConnection(stream, false, maxBody);
	}

	private static byte[] response(String headers, byte[] body) {
		final byte[] head = ("HTTP/1.0 200 OK\r\n"+ headers +"\r\n").getBytes(ASCII);
		final byte[] all = Arrays.copyOf(head, head.length + body.length);
		System.arraycopy(body, 0, all, head.length, body.length);
		return all;
	}

	private static void assertRejected(HttpConnection http, String messagePart) throws IOException {
		try {
			http.readResponse();
			fail("expected DirectoryRequestFailedException");
		} catch(DirectoryRequestFailedException e) {
			assertTrue(e.getMessage(), e.getMessage().contains(messagePart));
		}
	}

	private static byte[] deflate(byte[] data) {
		final Deflater d = new Deflater(Deflater.BEST_COMPRESSION);
		d.setInput(data);
		d.finish();
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		final byte[] buf = new byte[4096];
		while(!d.finished()) {
			out.write(buf, 0, d.deflate(buf));
		}
		d.end();
		return out.toByteArray();
	}

	@Test
	public void testNormalResponse() throws Exception {
		final byte[] body = "network-status-version 3\n".getBytes(ASCII);
		final HttpConnection http = connection(response("Content-Length: "+ body.length +"\r\n", body), 1000);
		http.readResponse();
		assertEquals(200, http.getStatusCode());
		assertEquals(body.length, http.getMessageBody().remaining());
	}

	@Test
	public void testContentLengthTooLarge() throws Exception {
		assertRejected(connection(response("Content-Length: 2147483647\r\n", new byte[0]), 1000), "outside");
		assertRejected(connection(response("Content-Length: 1001\r\n", new byte[0]), 1000), "outside");
	}

	@Test
	public void testContentLengthNegativeOrInvalid() throws Exception {
		assertRejected(connection(response("Content-Length: -1\r\n", new byte[0]), 1000), "outside");
		assertRejected(connection(response("Content-Length: 12abc\r\n", new byte[0]), 1000), "Invalid Content-Length");
	}

	@Test
	public void testBodyUntilEofTooLarge() throws Exception {
		assertRejected(connection(response("", new byte[5000]), 1000), "exceeds");
	}

	@Test
	public void testDecompressionBomb() throws Exception {
		// 10 MB of zeros compresses to about 10 KB.
		final byte[] bomb = deflate(new byte[10 * 1024 * 1024]);
		assertTrue(bomb.length < 20000);
		assertRejected(connection(response("Content-Encoding: deflate\r\nContent-Length: "+ bomb.length +"\r\n", bomb), 1024 * 1024), "Decompressed");
	}

	@Test
	public void testCompressedBodyWithinLimit() throws Exception {
		final byte[] plain = new byte[100000];
		final byte[] z = deflate(plain);
		final HttpConnection http = connection(response("Content-Encoding: deflate\r\nContent-Length: "+ z.length +"\r\n", z), 200000);
		http.readResponse();
		assertEquals(plain.length, http.getMessageBody().remaining());
	}

	@Test
	public void testLongHeaderLine() throws Exception {
		final char[] longValue = new char[HttpConnection.MAX_LINE_LENGTH + 10];
		Arrays.fill(longValue, 'a');
		assertRejected(connection(response("X-Junk: "+ new String(longValue) +"\r\n", new byte[0]), 1000), "longer than");
	}

	@Test
	public void testTooManyHeaders() throws Exception {
		final StringBuilder sb = new StringBuilder();
		for(int i = 0; sb.length() <= HttpConnection.MAX_HEADERS_SIZE; i++) {
			sb.append("X-H"+ i +": value\r\n");
		}
		assertRejected(connection(response(sb.toString(), new byte[0]), 1000), "headers exceed");
	}
}
