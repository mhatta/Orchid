package com.subgraph.orchid.connections;

import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.subgraph.orchid.misc.TrafficCounter;

/**
 * The streams of a connection to a relay, wrapped to count the bytes of
 * the cells read and written.  They sit above TLS, so the TLS records and
 * the TCP/IP headers are not counted.
 */
final class CountingStreams {
	private CountingStreams() {}

	static final class In extends FilterInputStream {
		private final TrafficCounter counter;

		In(InputStream in, TrafficCounter counter) {
			super(in);
			this.counter = counter;
		}

		@Override
		public int read() throws IOException {
			final int b = in.read();
			if(b >= 0) {
				counter.addBytesRead(1);
			}
			return b;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			final int n = in.read(b, off, len);
			counter.addBytesRead(n);
			return n;
		}

		@Override
		public long skip(long n) throws IOException {
			final long skipped = in.skip(n);
			counter.addBytesRead(skipped);
			return skipped;
		}

		/* No mark and reset: bytes read again would be counted twice. */
		@Override
		public boolean markSupported() {
			return false;
		}
	}

	static final class Out extends FilterOutputStream {
		private final TrafficCounter counter;

		Out(OutputStream out, TrafficCounter counter) {
			super(out);
			this.counter = counter;
		}

		@Override
		public void write(int b) throws IOException {
			out.write(b);
			counter.addBytesWritten(1);
		}

		/* FilterOutputStream would write the array a byte at a time. */
		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			out.write(b, off, len);
			counter.addBytesWritten(len);
		}
	}
}
