package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.InputStream;

public class SSLEngineInputStream extends InputStream {

	private final SSLEngineManager manager;
	
	SSLEngineInputStream(SSLEngineManager manager) {
		this.manager = manager;
	}
	
	@Override
	public int read() throws IOException {
		final byte[] b = new byte[1];
		if(manager.read(b, 0, 1) < 0) {
			return -1;
		}
		return b[0] & 0xFF;
	}
	
	/*
	 * A read of the manager never returns 0 for a non-empty request: a TLS
	 * record without application data (such as a TLS 1.3 NewSessionTicket)
	 * is not the end of the stream.
	 */
	@Override
	public int read(byte b[], int off, int len) throws IOException {
		if(off < 0 || len < 0 || off + len > b.length || off + len < 0) {
			throw new IndexOutOfBoundsException();
		}
		return manager.read(b, off, len);
	}

	@Override
	public void close() throws IOException {
		manager.close();
	}
}
