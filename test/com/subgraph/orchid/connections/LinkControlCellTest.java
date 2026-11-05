package com.subgraph.orchid.connections;

import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.Test;

import com.subgraph.orchid.Cell;
import com.subgraph.orchid.ConnectionIOException;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.circuits.cells.CellImpl;
import com.subgraph.orchid.config.TorConfigImpl;

/**
 * The link handshake cells are accepted only during the handshake, and
 * only a few of them.  They used to be queued without limit, also after
 * the handshake, so that a relay could fill the heap with CERTS cells.
 */
public class LinkControlCellTest {

	private static ConnectionImpl connection() throws Exception {
		final SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
		final Router router = createNiceMock(Router.class);
		replay(router);
		return new ConnectionImpl(new TorConfigImpl(), socket, router, null, false);
	}

	private static Cell certsCell() {
		return CellImpl.createVarCell(0, Cell.CERTS, 2);
	}

	@Test
	public void testCertsAfterHandshakeClosesConnection() throws Exception {
		final ConnectionImpl c = connection();
		c.setHandshakeComplete();
		try {
			c.processCell(certsCell());
			fail("CERTS after the handshake was accepted");
		} catch(ConnectionIOException e) {
			assertTrue(c.isClosed());
		}
	}

	@Test
	public void testTooManyHandshakeCellsCloseConnection() throws Exception {
		final ConnectionImpl c = connection();
		for(int i = 0; i < ConnectionImpl.MAX_QUEUED_CONTROL_CELLS; i++) {
			c.processCell(certsCell());
		}
		assertFalse(c.isClosed());
		try {
			c.processCell(certsCell());
			fail("the queue of handshake cells has no limit");
		} catch(ConnectionIOException e) {
			assertTrue(c.isClosed());
		}
	}

	@Test
	public void testPaddingAfterHandshakeIsIgnored() throws Exception {
		final ConnectionImpl c = connection();
		c.setHandshakeComplete();
		for(int i = 0; i < 100; i++) {
			c.processCell(CellImpl.createVarCell(0, Cell.VPADDING, 16));
			c.processCell(CellImpl.createCell(0, Cell.PADDING));
		}
		assertFalse(c.isClosed());
	}
}
