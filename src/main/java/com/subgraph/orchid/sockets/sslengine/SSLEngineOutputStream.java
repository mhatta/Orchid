package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.OutputStream;

public class SSLEngineOutputStream extends OutputStream {

	private final SSLEngineManager manager;
	
	public SSLEngineOutputStream(SSLEngineManager manager) {
		this.manager = manager;
	}
	
	@Override
	public void write(int b) throws IOException {
		manager.write(new byte[] { (byte) b }, 0, 1);
	}
	
	@Override
	public void write(byte b[], int off, int len) throws IOException {
		if(off < 0 || len < 0 || off + len > b.length || off + len < 0) {
			throw new IndexOutOfBoundsException();
		}
		manager.write(b, off, len);
	}
	
	@Override
	public void close() throws IOException {
		manager.close();
	}
}
