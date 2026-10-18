package com.subgraph.orchid.circuits.hs;

import com.subgraph.orchid.HiddenServiceCircuit;
import com.subgraph.orchid.TorConfig;

/**
 * Client side state for one version 3 onion service: the identity key taken
 * from the onion address, the blinded key / subcredential derived for the
 * current time period, the last descriptor fetched and the rendezvous
 * circuit currently open to the service.
 */
public class HiddenService {

	private final TorConfig config;
	private final HSV3Address address;

	private HSV3TimePeriod timePeriod;
	private byte[] blindedPublicKey;
	private byte[] subcredential;
	private HSV3Descriptor descriptor;
	private HiddenServiceCircuit circuit;

	HiddenService(TorConfig config, HSV3Address address) {
		this.config = config;
		this.address = address;
	}

	HSV3Address getAddress() {
		return address;
	}

	String getOnionAddressForLogging() {
		if(config.getSafeLogging()) {
			return "[scrubbed]";
		} else {
			return address.getOnionAddress();
		}
	}

	String getOnionAddress() {
		return address.getOnionAddress();
	}

	/** The 32 byte ed25519 identity public key (KP_hs_id). */
	byte[] getIdentityPublicKey() {
		return address.getPublicKey();
	}

	/**
	 * (Re)compute the blinded key and subcredential for the given time period.
	 * Returns true if the time period changed since the last call.
	 */
	synchronized boolean updateTimePeriod(HSV3TimePeriod tp) {
		if(timePeriod != null && timePeriod.getPeriodNumber() == tp.getPeriodNumber() && timePeriod.getPeriodLengthMinutes() == tp.getPeriodLengthMinutes()) {
			timePeriod = tp;
			return false;
		}
		timePeriod = tp;
		blindedPublicKey = HSV3Crypto.blindedPublicKey(getIdentityPublicKey(), tp.getPeriodNumber(), tp.getPeriodLengthMinutes());
		subcredential = HSV3Crypto.subcredential(getIdentityPublicKey(), blindedPublicKey);
		descriptor = null;
		return true;
	}

	synchronized HSV3TimePeriod getTimePeriod() {
		return timePeriod;
	}

	/** KP_hs_blind_id for the current time period. */
	synchronized byte[] getBlindedPublicKey() {
		return blindedPublicKey;
	}

	/** N_hs_subcred for the current time period. */
	synchronized byte[] getSubcredential() {
		return subcredential;
	}

	/** The client's x25519 private key for restricted discovery (client authorization), or null. */
	byte[] getClientAuthPrivateKey() {
		return config.getOnionClientAuthKey(address.getOnionAddress());
	}

	synchronized boolean hasCurrentDescriptor() {
		return (descriptor != null && !descriptor.isExpired());
	}

	synchronized HSV3Descriptor getDescriptor() {
		return descriptor;
	}

	synchronized void setDescriptor(HSV3Descriptor descriptor) {
		this.descriptor = descriptor;
	}

	synchronized HiddenServiceCircuit getCircuit() {
		if(circuit != null && circuit.isMarkedForClose()) {
			circuit = null;
		}
		return circuit;
	}

	synchronized void setCircuit(HiddenServiceCircuit circuit) {
		this.circuit = circuit;
	}

	@Override
	public int hashCode() {
		return address.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		return (obj instanceof HiddenService) && ((HiddenService) obj).address.equals(address);
	}
}
