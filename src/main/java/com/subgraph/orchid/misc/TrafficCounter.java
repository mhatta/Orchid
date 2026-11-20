package com.subgraph.orchid.misc;

import java.util.concurrent.atomic.AtomicLong;

import com.subgraph.orchid.TrafficInfo;

/**
 * The byte counters of one {@link com.subgraph.orchid.TorClient}, shared
 * by its connections to relays and its streams.  Each TorClient has its
 * own, so that two clients in one process do not add up.
 *
 * @see TrafficInfo
 */
@ThreadSafe
public final class TrafficCounter {
	private final AtomicLong bytesRead = new AtomicLong();
	private final AtomicLong bytesWritten = new AtomicLong();
	private final AtomicLong streamBytesRead = new AtomicLong();
	private final AtomicLong streamBytesWritten = new AtomicLong();

	/** Bytes received from a relay. */
	public void addBytesRead(long n) {
		if(n > 0) {
			bytesRead.addAndGet(n);
		}
	}

	/** Bytes sent to a relay. */
	public void addBytesWritten(long n) {
		if(n > 0) {
			bytesWritten.addAndGet(n);
		}
	}

	/** Stream data received. */
	public void addStreamBytesRead(long n) {
		if(n > 0) {
			streamBytesRead.addAndGet(n);
		}
	}

	/** Stream data sent. */
	public void addStreamBytesWritten(long n) {
		if(n > 0) {
			streamBytesWritten.addAndGet(n);
		}
	}

	public TrafficInfo getTrafficInfo() {
		return new TrafficInfo(bytesRead.get(), bytesWritten.get(), streamBytesRead.get(), streamBytesWritten.get());
	}
}
