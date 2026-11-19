package com.subgraph.orchid.connections;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.fuzz.FuzzSupport;

/**
 * Fuzz target: the CERTS cell of the link handshake (its payload is the
 * input), and the Ed25519 certificates in it as Ed25519LinkAuthentication
 * checks them.  This is what a guard or bridge sends before Orchid knows
 * whether it is the relay it claims to be.
 */
public class CertsCellFuzzer {
	private static final RSAPublicKey RSA = rsaKey();
	private static final byte[] TLS_CERT = new byte[] { 1, 2, 3 };

	private static RSAPublicKey rsaKey() {
		try {
			final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(1024);
			return (RSAPublicKey) g.generateKeyPair().getPublic();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	public static void fuzzerTestOneInput(byte[] data) {
		FuzzSupport.quietLogging();
		final Cell cell = CellImpl.createVarCell(0, Cell.CERTS, data.length);
		cell.putByteArray(data);
		cell.resetToPayload();
		final ConnectionHandshakeV3.CertsCell certs;
		try {
			certs = ConnectionHandshakeV3.parseCertsCell(cell);
		} catch (ConnectionHandshakeException e) {
			return;
		}
		if(certs.ed25519SigningCertificate == null && certs.ed25519TlsLinkCertificate == null
				&& certs.rsaEd25519CrossCertificate == null) {
			return;
		}
		try {
			Ed25519LinkAuthentication.verify(certs.ed25519SigningCertificate, certs.ed25519TlsLinkCertificate,
					certs.rsaEd25519CrossCertificate, RSA, TLS_CERT, 1800000000L);
		} catch (ConnectionHandshakeException e) {
			// refused
		}
	}
}
