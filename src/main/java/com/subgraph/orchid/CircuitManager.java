package com.subgraph.orchid;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeoutException;

import com.subgraph.orchid.data.IPv4Address;


public interface CircuitManager {

	static int DIRECTORY_PURPOSE_CONSENSUS = 1;
	static int DIRECTORY_PURPOSE_CERTIFICATES = 2;
	static int DIRECTORY_PURPOSE_DESCRIPTORS = 3;
	
	/**
	 * Begin automatically building new circuits in the background.
	 */
	void startBuildingCircuits();
	void stopBuildingCircuits(boolean killCircuits);

	/**
	 * The network changed: entry guards marked unreachable are tried again
	 * before new ones are chosen.  The default implementation does nothing.
	 */
	default void networkChanged() {
	}

	/**
	 * Use new circuits for all streams opened from now on, as Tor's NEWNYM
	 * signal does.  Streams already open are not interrupted: the circuits
	 * they use take no new streams and are closed when the streams end.
	 * At most one new identity takes effect every 10 seconds, as in Tor; one
	 * asked for sooner is delayed, and merged with any other asked for in
	 * the meantime.  The default implementation does nothing.
	 *
	 * @return 0 if the new identity took effect now, or the milliseconds
	 *         until it does
	 * @since 2.8.0
	 */
	default long newIdentity() {
		return 0;
	}

	/**
	 * A snapshot of the circuits: see {@link TorClient#getCircuits()}.  The
	 * default implementation returns an empty list.
	 *
	 * @since 2.8.0
	 */
	default List<CircuitInfo> getCircuitInfo() {
		return Collections.emptyList();
	}

	/**
	 * A snapshot of the sampled entry guards: see
	 * {@link TorClient#getEntryGuards()}.  The default implementation
	 * returns an empty list.
	 *
	 * @since 2.8.0
	 */
	default List<GuardInfo> getEntryGuardInfo() {
		return Collections.emptyList();
	}
	/**
	 * Attempt to open an exit stream to the specified destination <code>hostname</code> and
	 * <code>port</code>.
	 * 
	 * @param hostname The name of the host to open an exit connection to.
	 * @param port The port to open an exit connection to.
	 * @return The status response result of attempting to open the exit connection.
	 */
	Stream openExitStreamTo(String hostname, int port) throws InterruptedException, TimeoutException, OpenFailedException;

	/**
	 * Attempt to open an exit stream to the destination specified by <code>address</code> and
	 * <code>port</code>.
	 * 
	 * @param address The address to open an exit connection to.
	 * @param port The port to open an exit connection to.
	 * @return The status response result of attempting the open the exit connection.
	 */
	Stream openExitStreamTo(IPv4Address address, int port) throws InterruptedException, TimeoutException, OpenFailedException;

	/**
	 * Open a stream as {@link #openExitStreamTo(String, int)} does, on a
	 * circuit that carries only streams with the same isolation key.
	 * Streams with different keys (including null, the key of streams
	 * opened without one) never share a circuit, to an exit or to an onion
	 * service.  The SOCKS port uses the client's SOCKS credentials as the
	 * key, as Tor's IsolateSOCKSAuth does.
	 *
	 * The default implementation supports only a null key.
	 *
	 * @param isolationKey any string; null for the shared, unisolated circuits
	 */
	default Stream openExitStreamTo(String hostname, int port, String isolationKey) throws InterruptedException, TimeoutException, OpenFailedException {
		if(isolationKey != null) {
			throw new OpenFailedException("Stream isolation is not supported by "+ getClass().getName());
		}
		return openExitStreamTo(hostname, port);
	}

	/** See {@link #openExitStreamTo(String, int, String)}. */
	default Stream openExitStreamTo(IPv4Address address, int port, String isolationKey) throws InterruptedException, TimeoutException, OpenFailedException {
		if(isolationKey != null) {
			throw new OpenFailedException("Stream isolation is not supported by "+ getClass().getName());
		}
		return openExitStreamTo(address, port);
	}
	
	
	Stream openDirectoryStream(int purpose) throws InterruptedException, TimeoutException, OpenFailedException;
	
	Stream openDirectoryStream() throws InterruptedException, TimeoutException, OpenFailedException;
	
	DirectoryCircuit openDirectoryCircuit() throws OpenFailedException;
	Circuit getCleanInternalCircuit() throws InterruptedException;
	
	ExitCircuit openExitCircuitTo(List<Router> path) throws OpenFailedException;
	InternalCircuit openInternalCircuitTo(List<Router> path) throws OpenFailedException;
	DirectoryCircuit openDirectoryCircuitTo(List<Router> path) throws OpenFailedException;
}
