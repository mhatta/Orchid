package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class SSLEngineInputStream extends InputStream {

	private final SSLEngineManager manager;
	private final ByteBuffer recvBuffer;
	private boolean isEOF;
	
	SSLEngineInputStream(SSLEngineManager manager) {
		this.manager = manager;
		this.recvBuffer = manager.getRecvBuffer();
	}
	
	@Override
	public int read() throws IOException {
		if(!fillRecvBufferIfEmpty()) {
			return -1;
		}
		final int b = recvBuffer.get() & 0xFF;
		recvBuffer.compact();
		return b;
	}
	
	@Override
    public int read(byte b[], int off, int len) throws IOException {
		if(len == 0) {
			return 0;
		}
		if(!fillRecvBufferIfEmpty()) {
			return -1;
		}
		final int copyLen = Math.min(recvBuffer.remaining(), len);
		recvBuffer.get(b, off, copyLen);
		recvBuffer.compact();
		return copyLen;
    }

	@Override
	public void close() throws IOException {
		manager.close();
	}

	/*
	 * Make sure recvBuffer holds data and flip it for reading; return false
	 * at the end of the stream.  recvBuffer is kept in write mode between
	 * calls (the reads above compact() it after taking from it).
	 *
	 * A read of the manager that produces no data is not the end of the
	 * stream: it used to be taken for one, so that a TLS 1.3 connection
	 * ended as soon as the server's NewSessionTicket arrived.
	 */
	private boolean fillRecvBufferIfEmpty() throws IOException {
		if(isEOF) {
			return false;
		}
		while(recvBuffer.position() == 0) {
			if(manager.read() < 0) {
				isEOF = true;
				return false;
			}
		}
		recvBuffer.flip();
		return true;
	}
}
