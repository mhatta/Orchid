package com.subgraph.orchid.http;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/** The Host header carries the port when the URL names a non-default one. */
public class TorSocketStreamTest {
	private static TorSocketStream stream(String url) {
		return new TorSocketStream(url, null) {
			public void executeRequest() {
			}
		};
	}

	@Test
	public void testDefaultPortIsLeftOut() {
		assertEquals("example.com", stream("https://example.com/a").getHostHeader(443));
		assertEquals("example.com", stream("https://example.com:443/a").getHostHeader(443));
		assertEquals("example.com", stream("http://example.com/a").getHostHeader(80));
	}

	@Test
	public void testOtherPortIsIncluded() {
		assertEquals("example.com:8443", stream("https://example.com:8443/a").getHostHeader(443));
		assertEquals("example.com:8080", stream("http://example.com:8080/a?b=c").getHostHeader(80));
	}

	@Test
	public void testPort() {
		assertEquals(443, stream("https://example.com/a").getPort(443));
		assertEquals(8443, stream("https://example.com:8443/a").getPort(443));
	}
}
