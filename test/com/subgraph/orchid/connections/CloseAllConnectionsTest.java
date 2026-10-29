package com.subgraph.orchid.connections;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.After;
import org.junit.Test;

import com.subgraph.orchid.ConnectionFailedException;
import com.subgraph.orchid.ConnectionHandshakeException;
import com.subgraph.orchid.ConnectionTimeoutException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.config.TorConfigImpl;
import com.subgraph.orchid.data.IPv4Address;

/**
 * ConnectionCache#closeAllConnections() (used by
 * TorClient#notifyNetworkChanged()) and close() abort connections that are
 * still in the handshake instead of leaving them until the handshake
 * timeout, and closeAllConnections() keeps the cache usable.
 */
public class CloseAllConnectionsTest {
	private SSLServerSocket server;
	private final List<Socket> accepted = new ArrayList<Socket>();
	private ConnectionCacheImpl cache;

	@After
	public void after() throws IOException {
		if(cache != null) {
			cache.close();
		}
		if(server != null) {
			server.close();
		}
		synchronized(accepted) {
			for(Socket s: accepted) {
				s.close();
			}
		}
	}

	/* A TLS server that completes the TLS handshake and then says nothing (no VERSIONS cell). */
	private void startSilentRelay() throws Exception {
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new ByteArrayInputStream(java.util.Base64.getDecoder().decode(ConnectionSocketFactoryTest.RELAY_KEYSTORE_BASE64)), "orchid".toCharArray());
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		kmf.init(ks, "orchid".toCharArray());
		final SSLContext context = SSLContext.getInstance("TLS");
		context.init(kmf.getKeyManagers(), null, null);
		server = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					while(true) {
						final SSLSocket s = (SSLSocket) server.accept();
						synchronized(accepted) {
							accepted.add(s);
						}
						try {
							s.startHandshake();
						} catch(IOException e) {
							// the client went away
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

	private Router router() {
		final Router router = createNiceMock(Router.class);
		expect(router.getAddress()).andStubReturn(new IPv4Address(0x7F000001));
		expect(router.getOnionPort()).andStubReturn(server.getLocalPort());
		expect(router.getNickname()).andStubReturn("silent");
		replay(router);
		return router;
	}

	private int acceptedCount() {
		synchronized(accepted) {
			return accepted.size();
		}
	}

	/* Start a connection in another thread; the latch opens when it ends, with its exception. */
	private CountDownLatch connectInBackground(final Router router, final AtomicReference<Throwable> failure) {
		final CountDownLatch done = new CountDownLatch(1);
		final Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					cache.getConnectionTo(router, false);
				} catch(Throwable e) {
					failure.set(e);
				} finally {
					done.countDown();
				}
			}
		});
		t.setDaemon(true);
		t.start();
		return done;
	}

	private void waitForAccepted(int n) throws InterruptedException {
		final long deadline = System.currentTimeMillis() + 5000;
		while(acceptedCount() < n && System.currentTimeMillis() < deadline) {
			Thread.sleep(20);
		}
		assertEquals(n, acceptedCount());
		// let the TLS handshake finish, so that the client waits for VERSIONS
		Thread.sleep(300);
	}

	private static void assertConnectionFailure(Throwable t) {
		assertTrue(String.valueOf(t), t instanceof ConnectionHandshakeException
				|| t instanceof ConnectionFailedException || t instanceof ConnectionTimeoutException);
	}

	@Test(timeout = 30000)
	public void testCloseAllConnectionsAbortsPendingConnection() throws Exception {
		startSilentRelay();
		cache = new ConnectionCacheImpl(new TorConfigImpl(), null);
		final Router router = router();

		final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
		final CountDownLatch done = connectInBackground(router, failure);
		waitForAccepted(1);
		assertFalse(done.await(0, TimeUnit.MILLISECONDS));

		cache.closeAllConnections();
		assertTrue("the connection in progress was not aborted", done.await(3, TimeUnit.SECONDS));
		assertConnectionFailure(failure.get());
		assertFalse(cache.isClosed());

		// The cache still works: a new connection is attempted.
		final AtomicReference<Throwable> failure2 = new AtomicReference<Throwable>();
		final CountDownLatch done2 = connectInBackground(router, failure2);
		waitForAccepted(2);

		cache.close();
		assertTrue("close() did not abort the connection in progress", done2.await(3, TimeUnit.SECONDS));
		assertConnectionFailure(failure2.get());
	}
}
