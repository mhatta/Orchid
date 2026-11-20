package com.subgraph.orchid;

/**
 * How many bytes a {@link TorClient} has sent and received, for showing
 * data usage and bandwidth to users.  See {@link TorClient#getTrafficInfo()}.
 *
 * <p>There are two pairs of counters.
 *
 * <ul>
 * <li>{@link #getBytesRead()} and {@link #getBytesWritten()} count what
 * goes over the network: the cells received from and sent to relays (entry
 * guards, bridges and directory caches), including the link handshakes,
 * circuit building, directory downloads and padding.  They do not count the
 * TLS records and the TCP/IP headers the cells travel in, which add a few
 * per cent; the data usage that Android shows for the app includes them.
 * <li>{@link #getStreamBytesRead()} and {@link #getStreamBytesWritten()}
 * count the data of the streams that applications open: through the SOCKS
 * or HTTP CONNECT port, {@link TorClient#getSocketFactory()} or
 * {@link TorClient#openExitStreamTo(String, int)}, to the Internet or to
 * onion services.  Directory requests are not counted here.
 * </ul>
 *
 * <p>The difference between the two is what Tor costs: cell headers,
 * circuit building, directory downloads, flow control and padding.
 *
 * <p>The counters start at zero when the <code>TorClient</code> is created
 * and only grow; {@link TorClient#newIdentity()} and
 * {@link TorClient#notifyNetworkChanged()} do not reset them.  To show a
 * rate, take two snapshots and divide the difference by the time between
 * them.
 *
 * <p>The totals say nothing about where the traffic went, but they do show
 * when the user is active.  Do not hand them to other apps (an exported
 * content provider or broadcast) unless the user asks for it.
 *
 * @since 2.8.0
 */
public final class TrafficInfo {
	private final long bytesRead;
	private final long bytesWritten;
	private final long streamBytesRead;
	private final long streamBytesWritten;

	/** For Orchid's own use; applications get these from {@link TorClient}. */
	public TrafficInfo(long bytesRead, long bytesWritten, long streamBytesRead, long streamBytesWritten) {
		this.bytesRead = bytesRead;
		this.bytesWritten = bytesWritten;
		this.streamBytesRead = streamBytesRead;
		this.streamBytesWritten = streamBytesWritten;
	}

	/** Bytes received from relays, in cells. */
	public long getBytesRead() {
		return bytesRead;
	}

	/** Bytes sent to relays, in cells. */
	public long getBytesWritten() {
		return bytesWritten;
	}

	/** Bytes of stream data received, for applications. */
	public long getStreamBytesRead() {
		return streamBytesRead;
	}

	/** Bytes of stream data sent, from applications. */
	public long getStreamBytesWritten() {
		return streamBytesWritten;
	}

	@Override
	public String toString() {
		return "[TrafficInfo read="+ bytesRead +" written="+ bytesWritten
				+" streamRead="+ streamBytesRead +" streamWritten="+ streamBytesWritten +"]";
	}
}
