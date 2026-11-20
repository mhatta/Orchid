package com.subgraph.orchid;

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
	void stop();
}
