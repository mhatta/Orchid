package com.subgraph.orchid.sockets.sslengine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class SSLEngineSSLSocket extends SSLSocket implements HandshakeCallbackHandler {

	private final SSLEngine engine;
	private final SSLEngineManager manager;
	
	private Socket socket;
	private InputStream inputStream;
	private OutputStream outputStream;
	private final List<HandshakeCompletedListener> listenerList;
	/* Whether close() also closes socket. */
	private final boolean autoClose;
	private volatile boolean closed = false;
	/**
	 * A TLS socket over <code>socket</code> that checks that the server's
	 * certificate is valid for <code>host</code> (RFC 2818 / RFC 6125, as
	 * HttpsURLConnection does) and sends <code>host</code> in the SNI
	 * extension.  Use this constructor: over Tor the exit relay sits between
	 * the client and the server, so a certificate chain that is merely
	 * trusted, but issued for another name, must be rejected.
	 *
	 * The name is checked by the SSLEngine (endpoint identification) and,
	 * since not every platform's engine does that (Android's do not promise
	 * it), once more after the handshake by {@link HostnameChecker}.  If
	 * the check fails, the connection is closed and every read and write
	 * throws.
	 *
	 * @param host The name of the server, as the application asked for it.
	 * @param port The server's port.
	 */
	public SSLEngineSSLSocket(Socket socket, SSLContext context, String host, int port) throws IOException {
		this(socket, context, host, port, true);
	}

	/**
	 * As {@link #SSLEngineSSLSocket(Socket, SSLContext, String, int)}; with
	 * autoClose false, close() sends close_notify but leaves socket open
	 * (see {@link javax.net.ssl.SSLSocketFactory#createSocket(Socket, String, int, boolean)}).
	 */
	public SSLEngineSSLSocket(Socket socket, SSLContext context, String host, int port, boolean autoClose) throws IOException {
		this(socket, createSSLEngine(context, host, port), host, autoClose);
	}

	/**
	 * @deprecated Does not check the server's host name, so any trusted
	 * certificate is accepted, including one a malicious exit relay obtained
	 * for a domain of its own.  Use
	 * {@link #SSLEngineSSLSocket(Socket, SSLContext, String, int)}.
	 */
	@Deprecated
	public SSLEngineSSLSocket(Socket socket, SSLContext context) throws IOException {
		this(socket, createSSLEngine(context, null, -1), null, true);
	}

	private SSLEngineSSLSocket(Socket socket, SSLEngine engine, String verifyHost, boolean autoClose) throws IOException {
		this.engine = engine;
		this.socket = socket;
		this.autoClose = autoClose;
		this.manager = new SSLEngineManager(engine, this, socket.getInputStream(), socket.getOutputStream(), verifyHost);
		this.listenerList = new CopyOnWriteArrayList<HandshakeCompletedListener>();
	}

	/**
	 * True if the server closed the connection without a TLS close_notify.
	 * Reads report that as the end of the stream; but over Tor the exit
	 * relay can also cut a stream short, so a protocol that does not carry
	 * its own length should check this before it trusts what it read.
	 */
	public boolean wasTruncated() {
		return manager.wasTruncated();
	}

	private static SSLEngine createSSLEngine(SSLContext context, String host, int port) {
		if(host == null) {
			final SSLEngine engine = context.createSSLEngine();
			engine.setUseClientMode(true);
			return engine;
		}
		// The peer host and port also give SNI (for a host name, not an IP literal).
		final SSLEngine engine = context.createSSLEngine(host, port);
		engine.setUseClientMode(true);
		final SSLParameters parameters = engine.getSSLParameters();
		parameters.setEndpointIdentificationAlgorithm("HTTPS");
		engine.setSSLParameters(parameters);
		return engine;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return engine.getSupportedCipherSuites();
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return engine.getEnabledCipherSuites();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		engine.setEnabledCipherSuites(suites);
	}

	@Override
	public String[] getSupportedProtocols() {
		return engine.getSupportedProtocols();
	}

	@Override
	public String[] getEnabledProtocols() {
		return engine.getEnabledProtocols();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		engine.setEnabledProtocols(protocols);
	}

	@Override
	public SSLSession getSession() {
		return engine.getSession();
	}

	@Override
	public void addHandshakeCompletedListener(
			HandshakeCompletedListener listener) {
		listenerList.add(listener);
	}

	@Override
	public void removeHandshakeCompletedListener(
			HandshakeCompletedListener listener) {
		listenerList.remove(listener);
	}

	@Override
	public void startHandshake() throws IOException {
		manager.startHandshake();
	}

	@Override
	public void setUseClientMode(boolean mode) {
		engine.setUseClientMode(mode);
	}

	@Override
	public boolean getUseClientMode() {
		return engine.getUseClientMode();
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		engine.setNeedClientAuth(need);
	}

	@Override
	public boolean getNeedClientAuth() {
		return engine.getNeedClientAuth();
	}

	@Override
	public void setWantClientAuth(boolean want) {
		engine.setWantClientAuth(want);
	}

	@Override
	public boolean getWantClientAuth() {
		return engine.getWantClientAuth();
	}

	@Override
	public void connect(SocketAddress endpoint) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public void connect(SocketAddress endpoint, int timeout) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public void bind(SocketAddress bindpoint) throws IOException {
		throw new IOException("Socket is already connected");
	}

	@Override
	public InetAddress getInetAddress() {
		return socket.getInetAddress();
	}

	@Override
	public InetAddress getLocalAddress() {
		return socket.getLocalAddress();
	}

	@Override
	public int getPort() {
		return socket.getPort();
	}

	@Override
	public int getLocalPort() {
		return socket.getLocalPort();
	}

	@Override
	public SocketAddress getRemoteSocketAddress() {
		return socket.getRemoteSocketAddress();
	}

	@Override
	public SocketAddress getLocalSocketAddress() {
		return socket.getLocalSocketAddress();
	}

	@Override
	public void setTcpNoDelay(boolean on) throws SocketException {
		socket.setTcpNoDelay(on);
	}

	@Override
	public boolean getTcpNoDelay() throws SocketException {
		return socket.getTcpNoDelay();
	}

	@Override
	public void setSoLinger(boolean on, int linger) throws SocketException {
		socket.setSoLinger(on, linger);
	}

	@Override
	public int getSoLinger() throws SocketException {
		return socket.getSoLinger();
	}

	@Override
	public void setOOBInline(boolean on) throws SocketException {
		socket.setOOBInline(on);
	}

	@Override
	public boolean getOOBInline() throws SocketException {
		return socket.getOOBInline();
	}

	@Override
	public synchronized void setSoTimeout(int timeout) throws SocketException {
		socket.setSoTimeout(timeout);
	}

	@Override
	public synchronized int getSoTimeout() throws SocketException {
		return socket.getSoTimeout();
	}

	@Override
	public synchronized void setSendBufferSize(int size) throws SocketException {
		socket.setSendBufferSize(size);
	}

	@Override
	public synchronized int getSendBufferSize() throws SocketException {
		return socket.getSendBufferSize();
	}

	@Override
	public synchronized void setReceiveBufferSize(int size)
			throws SocketException {
		socket.setReceiveBufferSize(size);
	}

	@Override
	public synchronized int getReceiveBufferSize() throws SocketException {
		return socket.getReceiveBufferSize();
	}

	@Override
	public void setKeepAlive(boolean on) throws SocketException {
		socket.setKeepAlive(on);
	}

	@Override
	public boolean getKeepAlive() throws SocketException {
		return socket.getKeepAlive();
	}

	@Override
	public void setTrafficClass(int tc) throws SocketException {
		socket.setTrafficClass(tc);
	}

	@Override
	public int getTrafficClass() throws SocketException {
		return socket.getTrafficClass();
	}

	@Override
	public void setReuseAddress(boolean on) throws SocketException {
		socket.setReuseAddress(on);
	}

	@Override
	public boolean getReuseAddress() throws SocketException {
		return socket.getReuseAddress();
	}

	/**
	 * Send close_notify (unless a writer is stuck) and close the underlying
	 * socket, unless this socket was made with autoClose false.  May be
	 * called from any thread, also while another thread is blocked reading.
	 */
	@Override
	public void close() throws IOException {
		closed = true;
		try {
			manager.close(autoClose);
		} finally {
			if(autoClose) {
				socket.close();
			}
		}
	}

	@Override
	public boolean isClosed() {
		return closed || socket.isClosed();
	}

	@Override
	public void shutdownInput() throws IOException {
		throw new UnsupportedOperationException("shutdownInput() not supported on SSL Sockets");
	}

	@Override
	public void shutdownOutput() throws IOException {
		throw new UnsupportedOperationException("shutdownOutput() not supported on SSL Sockets");
	}

	@Override
	public boolean isInputShutdown() {
		return socket.isInputShutdown();
	}

	@Override
	public boolean isOutputShutdown() {
		return socket.isOutputShutdown();
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		engine.setEnableSessionCreation(flag);
	}

	@Override
	public boolean getEnableSessionCreation() {
		return engine.getEnableSessionCreation();
	}

	@Override
	public synchronized InputStream getInputStream() throws IOException {
		if(inputStream == null) {
			inputStream = new SSLEngineInputStream(manager);
		}
		return inputStream;
	}

	@Override
	public synchronized OutputStream getOutputStream() throws IOException {
		if(outputStream == null) {
			outputStream = new SSLEngineOutputStream(manager);
		}
		return outputStream;
	}

	public void handshakeCompleted() {
		if(listenerList.isEmpty()) {
			return;
		}
		final HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, engine.getSession());
		for(HandshakeCompletedListener listener: listenerList) {
			listener.handshakeCompleted(event);
		}
	}
}
