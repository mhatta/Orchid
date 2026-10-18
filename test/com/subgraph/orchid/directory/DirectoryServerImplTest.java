package com.subgraph.orchid.directory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.crypto.TorPrivateKey;
import com.subgraph.orchid.data.IPv4Address;

public class DirectoryServerImplTest {

	private static DirectoryServerImpl server(TestAuthority authority) {
		final DirectoryAuthorityStatus status = new DirectoryAuthorityStatus();
		status.setNickname("test");
		status.setAddress(IPv4Address.createFromString("192.0.2.1"));
		status.setRouterPort(443);
		status.setDirectoryPort(80);
		status.setIdentity(authority.getFingerprint());
		final DirectoryServerImpl ds = new DirectoryServerImpl(status);
		ds.setV3Ident(authority.getFingerprint());
		return ds;
	}

	/*
	 * After a signing key rotation the client holds certificates for the old
	 * and the new key; a signature must be checked with the certificate of
	 * the key it names.
	 */
	@Test
	public void testCertificateIsFoundBySigningKey() {
		final TestAuthority authority = new TestAuthority();
		final DirectoryServerImpl ds = server(authority);
		final TorPrivateKey oldKey = authority.newSigningKey();
		final TorPrivateKey newKey = authority.newSigningKey();
		final KeyCertificate oldCert = TestAuthority.parseCertificate(authority.certificate(oldKey, 24));
		final KeyCertificate newCert = TestAuthority.parseCertificate(authority.certificate(newKey, 1));
		ds.addCertificate(oldCert);
		ds.addCertificate(newCert);
		assertSame(oldCert, ds.getCertificateByFingerprint(oldKey.getPublicKey().getFingerprint()));
		assertSame(newCert, ds.getCertificateByFingerprint(newKey.getPublicKey().getFingerprint()));
		assertNull(ds.getCertificateByFingerprint(authority.newSigningKey().getPublicKey().getFingerprint()));
	}

	/* Certificates more than 48 hours older than the newest one are dropped. */
	@Test
	public void testOldCertificatesArePurged() {
		final TestAuthority authority = new TestAuthority();
		final DirectoryServerImpl ds = server(authority);
		final TorPrivateKey oldKey = authority.newSigningKey();
		final TorPrivateKey newKey = authority.newSigningKey();
		ds.addCertificate(TestAuthority.parseCertificate(authority.certificate(oldKey, 24 * 30)));
		ds.addCertificate(TestAuthority.parseCertificate(authority.certificate(newKey, 1)));
		assertEquals(1, ds.getCertificates().size());
		assertNotNull(ds.getCertificateByFingerprint(newKey.getPublicKey().getFingerprint()));
	}

	/* The same certificate downloaded twice is kept once. */
	@Test
	public void testDuplicateCertificateIsKeptOnce() {
		final TestAuthority authority = new TestAuthority();
		final DirectoryServerImpl ds = server(authority);
		final String text = authority.certificate(authority.newSigningKey(), 1);
		ds.addCertificate(TestAuthority.parseCertificate(text));
		ds.addCertificate(TestAuthority.parseCertificate(text));
		assertEquals(1, ds.getCertificates().size());
	}
}
