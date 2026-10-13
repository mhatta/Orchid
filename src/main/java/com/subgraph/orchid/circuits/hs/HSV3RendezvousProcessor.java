package com.subgraph.orchid.circuits.hs;

import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.InternalCircuit;
import com.subgraph.orchid.RelayCell;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.circuits.CircuitNodeImpl;
import com.subgraph.orchid.crypto.HSNtorKeyAgreement;
import com.subgraph.orchid.crypto.TorRandom;
import com.subgraph.orchid.logging.Logger;

/**
 * Client side of the rendezvous protocol for version 3 onion services
 * (rend-spec-v3 section 4): establish a rendezvous point with a random
 * cookie, then complete the hs-ntor handshake from the RENDEZVOUS2 cell and
 * append the resulting virtual hop to the circuit.
 */
public class HSV3RendezvousProcessor {
	private static final Logger logger = Logger.getInstance(HSV3RendezvousProcessor.class);

	static final int RENDEZVOUS_COOKIE_LEN = 20;
	private final static TorRandom random = new TorRandom();

	private final InternalCircuit circuit;
	private final byte[] cookie;

	HSV3RendezvousProcessor(InternalCircuit circuit) {
		this.circuit = circuit;
		this.cookie = random.getBytes(RENDEZVOUS_COOKIE_LEN);
	}

	boolean establishRendezvous() {
		final RelayCell cell = circuit.createRelayCell(RelayCell.RELAY_COMMAND_ESTABLISH_RENDEZVOUS, 0, circuit.getFinalCircuitNode());
		cell.putByteArray(cookie);
		circuit.sendRelayCell(cell);
		final RelayCell response = circuit.receiveRelayCell();
		if(response == null) {
			logger.info("Timeout waiting for RENDEZVOUS_ESTABLISHED");
			return false;
		} else if(response.getRelayCommand() != RelayCell.RELAY_COMMAND_RENDEZVOUS_ESTABLISHED) {
			logger.info("Response received from ESTABLISH_RENDEZVOUS was not expected acknowledgement, relay command: "+ response.getRelayCommand());
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Wait for RENDEZVOUS2 (HANDSHAKE_INFO = SERVER_PK Y [32] | AUTH [32]),
	 * complete the hs-ntor handshake and turn the circuit into a hidden
	 * service circuit.
	 */
	HiddenServiceCircuit processRendezvous2(HSNtorKeyAgreement kex) {
		final RelayCell cell = circuit.receiveRelayCell();
		if(cell == null) {
			logger.info("Timeout waiting for RENDEZVOUS2");
			return null;
		} else if (cell.getRelayCommand() != RelayCell.RELAY_COMMAND_RENDEZVOUS2) {
			logger.info("Unexpected relay cell type received while waiting for RENDEZVOUS2: "+ cell.getRelayCommand());
			return null;
		}
		if(cell.cellBytesRemaining() < HSNtorKeyAgreement.CURVE25519_KEY_LEN + HSNtorKeyAgreement.DIGEST256_LEN) {
			logger.info("RENDEZVOUS2 cell is too short");
			return null;
		}
		final byte[] serverPublic = new byte[HSNtorKeyAgreement.CURVE25519_KEY_LEN];
		final byte[] auth = new byte[HSNtorKeyAgreement.DIGEST256_LEN];
		cell.getByteArray(serverPublic);
		cell.getByteArray(auth);
		final byte[] keyMaterial = kex.completeHandshake(serverPublic, auth);
		if(keyMaterial == null) {
			logger.info("hs-ntor handshake authentication failed while connecting to hidden service");
			return null;
		}
		return circuit.connectHiddenService(CircuitNodeImpl.createAnonymousHSV3(circuit.getFinalCircuitNode(), keyMaterial));
	}

	byte[] getCookie() {
		return cookie;
	}

	Router getRendezvousRouter() {
		return circuit.getFinalCircuitNode().getRouter();
	}
}
