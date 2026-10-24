package com.subgraph.orchid.http.ssl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;

import javax.net.ssl.SSLContext;

import org.junit.Test;

import com.subgraph.orchid.ApplicationProperties;

public class EnforceSslCertificatesTest {

	@Test
	public void testNoBundledCertificates() {
		assertEquals(0, ApplicationProperties.getAdditionalSslCertificates().length);
	}

	@Test
	public void testContextUsesPlatformTrustStore() throws Exception {
		final SSLContext before = SSLContext.getDefault();
		assertNotNull(EnforceSslCertificates.getSSLContext());
		// Creating Orchid's context must not replace the JVM wide default
		assertSame(before, SSLContext.getDefault());
	}
}
