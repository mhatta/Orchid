package com.subgraph.orchid.connections;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionTimeoutException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.IPv4Address;

/**
 * A relay that stops answering during the TLS or the link handshake makes
 * the connection fail after the handshake timeout, and the socket is closed.
 */
public class ConnectionTimeoutTest {
	private static final long TIMEOUT = 1000;
	private ServerSocket server;
	private final List<Socket> accepted = new ArrayList<Socket>();

	@After
	public void after() throws IOException {
		if(server != null) {
			server.close();
		}
		for(Socket s: accepted) {
			s.close();
		}
	}

	/* Accept connections and then do nothing with them. */
	private void acceptAndStaySilent(final ServerSocket ss, final boolean doTls) {
		server = ss;
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					while(true) {
						final Socket s = ss.accept();
						synchronized(accepted) {
							accepted.add(s);
						}
						if(doTls) {
							((SSLSocket) s).startHandshake();
						}
					}
				} catch(IOException e) {
					// server closed
				}
			}
		});
		t.setDaemon(true);
		t.start();
	}

	private static SSLServerSocket relayLikeTlsServer() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(ConnectionSocketFactoryTest.RELAY_KEYSTORE_BASE64)), "orchid".toCharArray());
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, "orchid".toCharArray());
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		return (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
	}

	private ConnectionImpl connection(SSLSocket socket) {
		final Router router = createNiceMock(Router.class);
		expect(router.getAddress()).andStubReturn(new IPv4Address(0x7F000001));
		expect(router.getOnionPort()).andStubReturn(server.getLocalPort());
		expect(router.getNickname()).andStubReturn("silent");
		replay(router);
		final ConnectionImpl c = new ConnectionImpl(new TorConfigImpl(), socket, router, null, false);
		c.setHandshakeTimeout(TIMEOUT);
		return c;
	}

	@Test(timeout = 20000)
	public void testSilentDuringTlsHandshake() throws Exception {
		acceptAndStaySilent(new ServerSocket(0, 5, InetAddress.getLoopbackAddress()), false);
		final SSLSocket socket = new ConnectionSocketFactory().createSocket();
		final ConnectionImpl c = connection(socket);
		final long start = System.nanoTime();
		try {
			c.connect();
			fail("expected ConnectionTimeoutException");
		} catch(ConnectionTimeoutException expected) {
		}
		final long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		assertTrue("waited "+ waited +" ms", waited < TIMEOUT + 3000);
		assertTrue(socket.isClosed());
	}

	@Test(timeout = 20000)
	public void testSilentDuringLinkHandshake() throws Exception {
		acceptAndStaySilent(relayLikeTlsServer(), true);
		final SSLSocket socket = new ConnectionSocketFactory().createSocket();
		final ConnectionImpl c = connection(socket);
		final long start = System.nanoTime();
		try {
			c.connect();
			fail("expected ConnectionHandshakeException");
		} catch(ConnectionHandshakeException e) {
			assertTrue(e.getMessage(), e.getMessage().contains("Timed out"));
		}
		final long waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		assertTrue("waited "+ waited +" ms", waited < TIMEOUT + 3000);
		assertTrue(socket.isClosed());
	}
}
