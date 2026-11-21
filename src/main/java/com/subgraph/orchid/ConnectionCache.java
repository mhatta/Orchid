package com.subgraph.orchid;


public interface ConnectionCache {
	/**
	 * Returns a completed connection to the specified router.  If an open connection 
	 * to the requested router already exists it is returned, otherwise a new connection
	 * is opened. 
	 * 
	 * @param router The router to which a connection is requested.
	 * @param isDirectoryConnection Is this going to be used as a directory connection.
	 * @return a completed connection to the specified router.
	 * @throws InterruptedException if thread is interrupted while waiting for connection to complete.
	 * @throws ConnectionTimeoutException if timeout expires before connection completes. 
	 * @throws ConnectionFailedException if connection fails due to I/O error
	 * @throws ConnectionHandshakeException if connection fails because an error occurred during handshake phase
	 */
	Connection getConnectionTo(Router router, boolean isDirectoryConnection) throws InterruptedException, ConnectionTimeoutException, ConnectionFailedException, ConnectionHandshakeException;
	
	void close();

	/**
	 * Close every connection to a relay, including those still being
	 * opened, but keep the cache open for new connections.  The circuits on
	 * these connections are destroyed.
	 *
	 * The default implementation does nothing.
	 */
	default void closeAllConnections() {
	}

	boolean isClosed();

	/**
	 * Orchid became dormant, or woke up: ask the relays on every
	 * connection, and on those opened from now on, to stop padding while it
	 * is dormant, and to pad again (if {@link TorConfig#getConnectionPadding()}
	 * allows it) when it wakes up.  The default implementation does nothing.
	 *
	 * @since 2.8.0
	 */
	default void setDormant(boolean dormant) {
	}
}
