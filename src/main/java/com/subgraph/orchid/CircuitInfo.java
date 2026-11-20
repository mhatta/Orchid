package com.subgraph.orchid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A snapshot of one circuit, for showing to users: what it is for, how far
 * it is built, and through which relays.  See
 * {@link TorClient#getCircuits()}.
 *
 * <p>It never carries a stream isolation key, which can contain a SOCKS
 * user name and password; {@link #isIsolated()} says only whether there is
 * one.
 *
 * @since 2.8.0
 */
public final class CircuitInfo {
	/** What the circuit is used for. */
	public enum Purpose {
		/** Streams to the Internet through an exit relay. */
		EXIT,
		/** Directory requests (consensus, descriptors). */
		DIRECTORY,
		/** Built in advance for an onion service; not yet used. */
		INTERNAL,
		/** Fetching an onion service descriptor from an HSDir. */
		ONION_SERVICE_DIRECTORY,
		/** Talking to an onion service's introduction point. */
		ONION_SERVICE_INTRODUCTION,
		/** The rendezvous circuit that carries the streams to an onion service. */
		ONION_SERVICE
	}

	/** How far the circuit is. */
	public enum State {
		/** Being built; {@link CircuitInfo#getPath()} has the hops built so far. */
		BUILDING,
		/** Built and taking new streams. */
		OPEN,
		/** Takes no new streams and is closed when the streams on it end. */
		CLOSING,
		/** The build failed. */
		FAILED,
		/** Closed. */
		CLOSED
	}

	private final Purpose purpose;
	private final State state;
	private final List<RelayInfo> path;
	private final int streamCount;
	private final boolean isolated;
	private final int secondsDirty;

	/** For Orchid's own use; applications get these from {@link TorClient}. */
	public CircuitInfo(Purpose purpose, State state, List<RelayInfo> path, int streamCount, boolean isolated, int secondsDirty) {
		this.purpose = purpose;
		this.state = state;
		this.path = Collections.unmodifiableList(new ArrayList<RelayInfo>(path));
		this.streamCount = streamCount;
		this.isolated = isolated;
		this.secondsDirty = secondsDirty;
	}

	public Purpose getPurpose() {
		return purpose;
	}

	public State getState() {
		return state;
	}

	/** The relays of the circuit, the entry guard first. */
	public List<RelayInfo> getPath() {
		return path;
	}

	/** The number of streams open on the circuit. */
	public int getStreamCount() {
		return streamCount;
	}

	/**
	 * True if the circuit is used only by streams with one stream isolation
	 * key (for example one SOCKS user name and password).
	 */
	public boolean isIsolated() {
		return isolated;
	}

	/** Seconds since the circuit carried its first stream, or 0 if it has carried none. */
	public int getSecondsDirty() {
		return secondsDirty;
	}

	@Override
	public String toString() {
		return purpose + " " + state + " " + path;
	}
}
