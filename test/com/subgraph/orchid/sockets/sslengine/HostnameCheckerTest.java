package com.subgraph.orchid.sockets.sslengine;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;

/**
 * HostnameChecker against a certificate whose only subject common name is
 * cn-only.example.net and whose subject alternative names are
 *   DNS:example.com, DNS:*.example.org, DNS:*.com, DNS:f*o.example.net,
 *   DNS:xn--bcher-kva.example (b\u00fccher.example), IP:192.0.2.1
 * Made with:
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes
 *     -days 36500 -subj /CN=cn-only.example.net -addext subjectAltName=...
 */
public class HostnameCheckerTest {
	private final static String CERTIFICATE =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIB8TCCAZegAwIBAgIUdZ4PRMhkk8GQJNzLJ6T3YfW8lqEwCgYIKoZIzj0EAwIw\n" +
		"HjEcMBoGA1UEAwwTY24tb25seS5leGFtcGxlLm5ldDAgFw0yNjExMDYyMDE3NDda\n" +
		"GA8yMTI2MTAxMzIwMTc0N1owHjEcMBoGA1UEAwwTY24tb25seS5leGFtcGxlLm5l\n" +
		"dDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABISdgRZ81ykrY1KRBuy/Z8pzDgmc\n" +
		"ZgIyBjfh0u+rlhFQOtkAtpxGUu4FfleWA+9Tf6xiWCqFI3CFrP3hUI9YZnyjgbAw\n" +
		"ga0wHQYDVR0OBBYEFOoKwkSTPG2ojhy11a89s9RlXMQtMB8GA1UdIwQYMBaAFOoK\n" +
		"wkSTPG2ojhy11a89s9RlXMQtMA8GA1UdEwEB/wQFMAMBAf8wWgYDVR0RBFMwUYIL\n" +
		"ZXhhbXBsZS5jb22CDSouZXhhbXBsZS5vcmeCBSouY29tgg9mKm8uZXhhbXBsZS5u\n" +
		"ZXSCFXhuLS1iY2hlci1rdmEuZXhhbXBsZYcEwAACATAKBggqhkjOPQQDAgNIADBF\n" +
		"AiEA21jEUzGYurVloywhA3yrMOgsPFa3d4oTDVfcMDJOuZgCICF/ufthUgvZK1Rd\n" +
		"NhBOM7XPpmklapHbhBhypTeJEUHr\n" +
		"-----END CERTIFICATE-----\n";

	private static X509Certificate certificate;

	@BeforeClass
	public static void load() throws Exception {
		certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
				.generateCertificate(new ByteArrayInputStream(CERTIFICATE.getBytes("US-ASCII")));
	}

	private static void accepts(String host) {
		assertTrue(host, HostnameChecker.matches(host, certificate));
	}

	private static void refuses(String host) {
		assertFalse(host, HostnameChecker.matches(host, certificate));
	}

	@Test
	public void exactNames() {
		accepts("example.com");
		accepts("EXAMPLE.com");
		accepts("example.com.");
		refuses("www.example.com");
		refuses("example.co");
		refuses("xample.com");
	}

	@Test
	public void wildcards() {
		accepts("www.example.org");
		accepts("WWW.Example.ORG.");
		refuses("example.org");
		refuses("a.b.example.org");
		refuses(".example.org");
		// "*.com" covers a whole top-level domain and matches nothing
		refuses("anything.com");
		// a wildcard is the whole leftmost label or nothing
		refuses("foo.example.net");
		refuses("fo.example.net");
	}

	@Test
	public void internationalizedNames() {
		accepts("b\u00fccher.example");
		accepts("xn--bcher-kva.example");
		refuses("bucher.example");
	}

	@Test
	public void ipAddresses() {
		accepts("192.0.2.1");
		refuses("192.0.2.2");
		refuses("192.0.2.256");
		refuses("192.0.2");
		// a host name is not compared with the iPAddress entry, nor the other way round
		refuses("1.2.0.192.in-addr.arpa");
		// IPv6 literals are always refused
		refuses("::1");
		refuses("[2001:db8::1]");
	}

	@Test
	public void commonNameIsNotUsed() {
		refuses("cn-only.example.net");
	}

	@Test
	public void malformedNames() {
		refuses(null);
		refuses("");
		refuses(".");
		refuses("example..com");
	}
}
