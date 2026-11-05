package com.subgraph.orchid.sockets;

import java.net.SocketImpl;
import java.net.SocketImplFactory;

import com.subgraph.orchid.TorClient;

/**
 * A SocketImplFactory for {@link java.net.Socket#setSocketImplFactory}.
 *
 * @deprecated  Installing it sends every socket of the whole process
 *     through Tor, including those of libraries that do not expect it, and
 *     Socket#setSocketImplFactory itself is deprecated since Java 17.  Use
 *     {@link TorClient#getSocketFactory()} instead, which affects only the
 *     clients that are given the factory.  This class will be removed in
 *     Orchid 3.0.
 */
@Deprecated
public class OrchidSocketImplFactory implements SocketImplFactory {
	private final TorClient torClient;
	
	public OrchidSocketImplFactory(TorClient torClient) {
		this.torClient = torClient;
	}

	public SocketImpl createSocketImpl() {
		return new OrchidSocketImpl(torClient);
	}
}
