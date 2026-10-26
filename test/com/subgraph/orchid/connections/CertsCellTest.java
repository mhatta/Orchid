package com.subgraph.orchid.connections;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.circuits.cells.CellImpl;

/**
 * Parsing of the CERTS cell: only the X.509 certificates (types 1 and 2)
 * are given to the X.509 parser; malformed input is a handshake error.
 */
public class CertsCellTest {
	private static byte[] x509() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(ConnectionSocketFactoryTest.RELAY_KEYSTORE_BASE64)), "orchid".toCharArray());
		return ((X509Certificate) ks.getCertificate("relay")).getEncoded();
	}

	private static byte[] bytes(int n, int seed) {
		final byte[] b = new byte[n];
		for(int i = 0; i < n; i++) {
			b[i] = (byte) (seed + i * 7);
		}
		return b;
	}

	/* A CERTS cell with the given (type, body) pairs; ncerts may differ from the number of pairs. */
	private static Cell certsCell(int ncerts, Object... typeAndBody) {
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(ncerts);
		for(int i = 0; i < typeAndBody.length; i += 2) {
			final int type = (Integer) typeAndBody[i];
			final byte[] body = (byte[]) typeAndBody[i + 1];
			out.write(type);
			out.write(body.length >> 8);
			out.write(body.length & 0xFF);
			out.write(body, 0, body.length);
		}
		final byte[] payload = out.toByteArray();
		final Cell cell = CellImpl.createVarCell(0, Cell.CERTS, payload.length);
		cell.putByteArray(payload);
		cell.resetToPayload();
		return cell;
	}

	@Test
	public void testRelayCertsCell() throws Exception {
		final byte[] cert = x509();
		final byte[] signing = bytes(140, 1), tlsLink = bytes(104, 2), cross = bytes(170, 3);
		final ConnectionHandshakeV3.CertsCell certs = ConnectionHandshakeV3.parseCertsCell(certsCell(5,
				1, cert, 2, cert, 4, signing, 5, tlsLink, 7, cross));
		assertNotNull(certs.linkCertificate);
		assertNotNull(certs.identityCertificate);
		assertArrayEquals(signing, certs.ed25519SigningCertificate);
		assertArrayEquals(tlsLink, certs.ed25519TlsLinkCertificate);
		assertArrayEquals(cross, certs.rsaEd25519CrossCertificate);
	}

	@Test
	public void testTorCertificatesAreNotParsedAsX509() throws Exception {
		// Even a valid X.509 encoding in the type 4 slot is kept as raw bytes.
		final byte[] cert = x509();
		final ConnectionHandshakeV3.CertsCell certs = ConnectionHandshakeV3.parseCertsCell(certsCell(5,
				4, cert, 1, cert, 5, bytes(10, 4), 2, cert, 7, bytes(10, 5)));
		assertArrayEquals(cert, certs.ed25519SigningCertificate);
	}

	private static void assertRejected(String expectedMessagePart, Cell cell) {
		try {
			ConnectionHandshakeV3.parseCertsCell(cell);
			fail("expected ConnectionHandshakeException");
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage(), e.getMessage().contains(expectedMessagePart));
		}
	}

	@Test
	public void testMalformedX509IsAHandshakeError() throws Exception {
		assertRejected("Malformed link", certsCell(2, 1, bytes(50, 6), 2, x509()));
	}

	@Test
	public void testLengthPastEndOfCell() throws Exception {
		final byte[] cert = x509();
		final Cell cell = certsCell(2, 1, cert, 2, cert);
		// Claim a longer second certificate than the cell holds.
		final int offset = Cell.CELL_VAR_HEADER_LEN + 1 + 3 + cert.length + 1;
		cell.putShortAt(offset, cert.length + 1000);
		assertRejected("past the end", cell);
	}

	@Test
	public void testDuplicateType() throws Exception {
		final byte[] cert = x509();
		assertRejected("Duplicate", certsCell(5, 1, cert, 2, cert, 4, bytes(10, 7), 4, bytes(10, 8), 7, bytes(10, 9)));
	}

	@Test
	public void testMissingIdentityCertificate() throws Exception {
		final byte[] cert = x509();
		assertRejected("lacks", certsCell(2, 1, cert, 4, bytes(10, 1)));
	}

	@Test
	public void testWrongCount() throws Exception {
		final byte[] cert = x509();
		assertRejected("Expecting 2 or 5", certsCell(3, 1, cert, 2, cert, 4, bytes(10, 1)));
	}

	@Test
	public void testTruncatedHeader() throws Exception {
		// Two certificates announced, one present.
		assertRejected("Truncated", certsCell(2, 1, x509()));
	}
}
