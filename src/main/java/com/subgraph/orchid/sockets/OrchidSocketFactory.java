package com.subgraph.orchid.sockets;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.TorClient;

public class OrchidSocketFactory extends SocketFactory {
	private final TorClient torClient;
	private final boolean exceptionOnLocalBind;
	private final String isolationKey;
	
	public OrchidSocketFactory(TorClient torClient) {
		this(torClient, true);
	}

	public OrchidSocketFactory(TorClient torClient, boolean exceptionOnLocalBind) {
		this(torClient, exceptionOnLocalBind, null);
	}

	/**
	 * @param isolationKey sockets of this factory use circuits shared only
	 *        with streams with the same key (null: the shared circuits)
	 */
	public OrchidSocketFactory(TorClient torClient, boolean exceptionOnLocalBind, String isolationKey) {
		this.torClient = torClient;
		this.exceptionOnLocalBind = exceptionOnLocalBind;
		this.isolationKey = isolationKey;
	}

    @Override
    public Socket createSocket() throws IOException {
        return createSocketInstance();
    }

    @Override
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException {
        final Socket s = createSocketInstance();
        return connectOrchidSocket(s, host, port);
	}

	@Override
	public Socket createSocket(String host, int port, InetAddress localHost,
			int localPort) throws IOException, UnknownHostException {
		if(exceptionOnLocalBind) {
			throw new UnsupportedOperationException("Cannot bind to local address");
		}
		return createSocket(host, port);
	}

	@Override
	public Socket createSocket(InetAddress address, int port) throws IOException {
        final Socket s = createSocketInstance();
		return connectOrchidSocket(s, OrchidSocketImpl.addressToName(address), port);
	}

	@Override
	public Socket createSocket(InetAddress address, int port,
			InetAddress localAddress, int localPort) throws IOException {
		if(exceptionOnLocalBind) {
			throw new UnsupportedOperationException("Cannot bind to local address");
		}
		return createSocket(address, port);
	}

	/**
	 * A placeholder address for <code>hostname</code>, for HTTP clients
	 * that resolve names themselves before they connect, such as OkHttp.
	 * Return it from the client's DNS hook instead of resolving the name:
	 * a socket of this factory connected to it asks the exit relay to
	 * resolve and connect to <code>hostname</code>, so that the name never
	 * reaches the local DNS.  With OkHttp:
	 *
	 * <pre>
	 * new OkHttpClient.Builder()
	 *     .socketFactory(torClient.getSocketFactory("my-app"))
	 *     .dns(host -&gt; Collections.singletonList(OrchidSocketFactory.unresolvedAddress(host)))
	 *     .build();
	 * </pre>
	 *
	 * The address is 240.0.0.1, carrying the host name.  240.0.0.0/4 is
	 * reserved and not routed, so that a socket that does not come from
	 * this factory fails to connect to it, instead of reaching anything:
	 * an application that sets the DNS hook but forgets the socket factory
	 * gets an error.  (Before 2.5.0 the address was 0.0.0.0, which Linux
	 * and Android treat as the local machine.)
	 */
	public static InetAddress unresolvedAddress(String hostname) {
		try {
			return InetAddress.getByAddress(hostname, PLACEHOLDER_ADDRESS.clone());
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private final static byte[] PLACEHOLDER_ADDRESS = { (byte) 240, 0, 0, 1 };

	/** Whether <code>address</code> is a placeholder from {@link #unresolvedAddress(String)}. */
	static boolean isPlaceholder(InetAddress address) {
		final byte[] a = address.getAddress();
		return a.length == 4 && (a[0] & 0xFF) == 240;
	}

	private Socket connectOrchidSocket(Socket s, String host, int port) throws IOException {
		final SocketAddress endpoint = InetSocketAddress.createUnresolved(host, port);
		s.connect(endpoint);
		return s;
	}
	
	private Socket createSocketInstance() throws SocketException {
		final OrchidSocketImpl impl = new OrchidSocketImpl(torClient, isolationKey);
		if(Tor.isAndroidRuntime()) {
			return new AndroidSocket(impl);
		} else {
			// call protected constructor
			return new Socket(impl) {};
		}
	}
}
