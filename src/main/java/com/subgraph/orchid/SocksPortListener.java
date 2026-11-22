package com.subgraph.orchid;

import java.net.ServerSocket;

public interface SocksPortListener {
	void addListeningPort(int port);

	/**
	 * Listen on <code>port</code> for HTTP CONNECT requests, for clients
	 * that can use only an HTTP proxy.  The default implementation throws
	 * UnsupportedOperationException.
	 *
	 * @since 2.8.0
	 */
	default void addHttpTunnelPort(int port) {
		throw new UnsupportedOperationException("addHttpTunnelPort");
	}

	/**
	 * Accept SOCKS clients on a server socket that the caller has bound and
	 * keeps: {@link #stop()} stops accepting on it but does not close it.
	 * See {@link TorClient#enableSocksListener(ServerSocket)}.  The default
	 * implementation throws UnsupportedOperationException.
	 *
	 * @since 2.9.0
	 */
	default void addListeningSocket(ServerSocket socket) {
		throw new UnsupportedOperationException("addListeningSocket");
	}

	/**
	 * As {@link #addListeningSocket(ServerSocket)}, for HTTP CONNECT
	 * clients.  The default implementation throws
	 * UnsupportedOperationException.
	 *
	 * @since 2.9.0
	 */
	default void addHttpTunnelSocket(ServerSocket socket) {
		throw new UnsupportedOperationException("addHttpTunnelSocket");
	}

	/**
	 * What the ports have been asked so far.  The default implementation
	 * returns no requests.
	 *
	 * @since 2.9.0
	 */
	default ProxyStatistics getStatistics() {
		return ProxyStatistics.empty();
	}

	void stop();
}
