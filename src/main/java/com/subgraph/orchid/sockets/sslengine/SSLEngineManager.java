package com.subgraph.orchid.sockets.sslengine;

import com.subgraph.orchid.logging.Logger;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * Drives an SSLEngine over a pair of plain streams.
 *
 * One thread may read while another writes, as with any socket: the
 * receiving side (peerApplicationBuffer, peerNetworkBuffer) is guarded by
 * readLock and the sending side (myApplicationBuffer, myNetworkBuffer) by
 * writeLock.  A thread that needs both, to run the initial handshake or to
 * answer a post-handshake message such as a TLS 1.3 KeyUpdate while
 * reading, always takes readLock first.  Only the initial handshake reads
 * from the network on behalf of the handshake; afterwards handshake records
 * are unwrapped by whichever thread reads, and a writer never blocks on the
 * network for input.
 */
public class SSLEngineManager {
    private static final Logger logger = Logger.getInstance(SSLEngineManager.class);

    /** How long close() waits for a writer before closing without close_notify. */
    private static final long CLOSE_LOCK_TIMEOUT = 1000;

    /** How long write() waits for an engine that sends nothing (see waitForEngine()). */
    private static final long WRITE_STALL_TIMEOUT = 30 * 1000;

    private final SSLEngine engine;
    private final InputStream input;
    private final OutputStream output;

    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();

    /* guarded by readLock */
    private final ByteBuffer peerApplicationBuffer;
    private final ByteBuffer peerNetworkBuffer;
    private boolean inputEOF = false;

    /* guarded by writeLock */
    private final ByteBuffer myApplicationBuffer;
    private final ByteBuffer myNetworkBuffer;
    private final ByteBuffer emptyBuffer = ByteBuffer.allocate(0);

    private final HandshakeCallbackHandler handshakeCallback;

    /*
     * Serializes the initial handshake.  A thread waits here, not on
     * readLock, for a handshake in progress: a reader holds readLock while
     * it blocks on the network, so a writer waiting for readLock after the
     * handshake would wait for as long as no data arrives, and no data
     * arrives when the peer waits for that writer.
     */
    private final Object handshakeLock = new Object();
    /* Set when the initial handshake has ended, successfully or not. */
    private volatile boolean handshakeDone = false;


    SSLEngineManager(SSLEngine engine, HandshakeCallbackHandler handshakeCallback, InputStream input, OutputStream output) {
        this.engine = engine;
        this.handshakeCallback = handshakeCallback;
        this.input = input;
        this.output = output;
        final SSLSession session = engine.getSession();
        this.peerApplicationBuffer = createApplicationBuffer(session);
        this.peerNetworkBuffer = createPacketBuffer(session);
        this.myApplicationBuffer = createApplicationBuffer(session);
        this.myNetworkBuffer = createPacketBuffer(session);
    }
	
    private static ByteBuffer createApplicationBuffer(SSLSession session) {
        return createBuffer(session.getApplicationBufferSize());
    }
	
    private static ByteBuffer createPacketBuffer(SSLSession session) {
        return createBuffer(session.getPacketBufferSize());
    }
	
    private static ByteBuffer createBuffer(int sz) {
        final byte[] array = new byte[sz];
        return ByteBuffer.wrap(array);
    }

    /**
     * Run the initial handshake, unless it already ran.  A thread that
     * calls this while another runs the handshake waits until it has
     * ended.  Reads and writes of application data start only after it
     * (see ensureHandshake()), so no other thread holds readLock or
     * writeLock here; both are taken because the handshake uses the
     * buffers they guard.
     */
    void startHandshake() throws IOException {
        synchronized(handshakeLock) {
            if(handshakeDone) {
                return;
            }
            readLock.lock();
            try {
                writeLock.lock();
                try {
                    logger.debug("startHandshake()");
                    engine.beginHandshake();
                    runHandshake(true);
                } finally {
                    writeLock.unlock();
                }
            } finally {
                readLock.unlock();
                handshakeDone = true;
            }
        }
    }

    /* Must be called without holding readLock or writeLock. */
    private void ensureHandshake() throws IOException {
        if(!handshakeDone) {
            startHandshake();
        }
    }

    /**
     * Encrypt and send len bytes of b.  Returns when all of them have been
     * written to the network.
     */
    void write(byte[] b, int off, int len) throws IOException {
        ensureHandshake();
        writeLock.lock();
        try {
            int written = 0;
            while(written < len) {
                final int n = Math.min(len - written, myApplicationBuffer.remaining());
                myApplicationBuffer.put(b, off + written, n);
                written += n;
                wrapApplicationData();
            }
        } finally {
            writeLock.unlock();
        }
    }

    /* Called with writeLock held: wrap and send everything in myApplicationBuffer. */
    private void wrapApplicationData() throws IOException {
        long stalledSince = 0;
        while(myApplicationBuffer.position() > 0) {
            myApplicationBuffer.flip();
            final SSLEngineResult result = engine.wrap(myApplicationBuffer, myNetworkBuffer);
            myApplicationBuffer.compact();
            logResult(result);

            switch(result.getStatus()) {
            case BUFFER_OVERFLOW:
                if(myNetworkBuffer.position() == 0) {
                    throw new SSLException("TLS record larger than the network buffer ("+ myNetworkBuffer.capacity() +" bytes)");
                }
                break;
            case CLOSED:
                throw new SSLException("SSLEngine is closed");
            default:
                break;
            }

            flush();
            runHandshake(false);

            if(result.bytesConsumed() > 0 || result.bytesProduced() > 0 || result.getStatus() == Status.BUFFER_OVERFLOW) {
                stalledSince = 0;
            } else {
                stalledSince = waitForEngine(stalledSince);
            }
        }
    }

    /*
     * wrap() consumed and produced nothing.  This happens while the reading
     * thread processes a post-handshake message (a TLS 1.3 NewSessionTicket
     * or KeyUpdate): the engine asks for a delegated task, which the reader
     * may already be running, or for more input, which only the reader can
     * unwrap.  Wait a little and try again, but not forever.
     */
    private long waitForEngine(long stalledSince) throws IOException {
        final long now = System.currentTimeMillis();
        if(stalledSince == 0) {
            stalledSince = now;
        } else if(now - stalledSince > WRITE_STALL_TIMEOUT) {
            throw new SSLException("TLS engine sends no data (handshake status "+ engine.getHandshakeStatus() +")");
        }
        if(engine.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            synchronousRunDelegatedTasks();
            return stalledSince;
        }
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("Interrupted while waiting for the TLS engine");
        }
        return stalledSince;
    }

    /**
     * Read up to len bytes of application data into b.  Returns the number
     * of bytes read, which is more than zero unless len is zero, or -1 at
     * the end of the stream.
     */
    int read(byte[] b, int off, int len) throws IOException {
        if(len == 0) {
            return 0;
        }
        ensureHandshake();
        readLock.lock();
        try {
            while(peerApplicationBuffer.position() == 0) {
                if(inputEOF) {
                    return -1;
                }
                if(readRecords() < 0) {
                    inputEOF = true;
                    return -1;
                }
            }
            peerApplicationBuffer.flip();
            final int n = Math.min(len, peerApplicationBuffer.remaining());
            peerApplicationBuffer.get(b, off, n);
            peerApplicationBuffer.compact();
            return n;
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Read application data from the peer into peerApplicationBuffer.
     * Called with readLock held.
     *
     * Returns the number of bytes added to peerApplicationBuffer, which is
     * always more than zero, or -1 at the end of the stream.
     *
     * TLS records are unwrapped until one of them carries application data.
     * Records without any are common: TLS 1.3 servers send NewSessionTicket
     * messages after the handshake, and a KeyUpdate may come at any time.
     * A record that has only partly arrived (BUFFER_UNDERFLOW) is completed
     * from the network.  Records already received are unwrapped before the
     * network is read again, so that data the peer has sent is never left
     * waiting in peerNetworkBuffer while we block on the socket.
     */
    private int readRecords() throws IOException {
        logger.debug("readRecords()");

        while(true) {
            if(engine.isInboundDone()) {
                return -1;
            }

            if(peerNetworkBuffer.position() > 0) {
                final int p = peerApplicationBuffer.position();
                peerNetworkBuffer.flip();
                final SSLEngineResult result = engine.unwrap(peerNetworkBuffer, peerApplicationBuffer);
                peerNetworkBuffer.compact();
                logResult(result);
                final int produced = peerApplicationBuffer.position() - p;

                switch(result.getStatus()) {
                case BUFFER_OVERFLOW:
                    // peerApplicationBuffer is only read into when it is empty
                    throw new SSLException("TLS record larger than the application buffer ("+ peerApplicationBuffer.capacity() +" bytes)");

                case CLOSED:
                    // close_notify from the peer
                    runHandshake(false);
                    return (produced > 0) ? produced : -1;

                case OK:
                    // Answer whatever the record asked for (a KeyUpdate needs a reply).
                    runHandshake(false);
                    if(produced > 0) {
                        return produced;
                    }
                    if(result.bytesConsumed() > 0) {
                        // A record without application data: look at the next one.
                        continue;
                    }
                    break;

                case BUFFER_UNDERFLOW:
                default:
                    break;
                }
            }

            // Not a complete record in peerNetworkBuffer: read more of it.
            if(!peerNetworkBuffer.hasRemaining()) {
                throw new SSLException("TLS record larger than the network buffer ("+ peerNetworkBuffer.capacity() +" bytes)");
            }
            if(networkReadBuffer(peerNetworkBuffer) < 0) {
                /*
                 * The connection was closed without a close_notify.  As
                 * before, this is reported as the end of the stream (many
                 * HTTP servers close this way); SSLEngine#closeInbound() is
                 * not called because it would throw for the truncation.
                 */
                return -1;
            }
        }
    }

    /**
     * Send close_notify and close the underlying output stream.
     *
     * A reader blocked on the network holds readLock, so this takes only
     * writeLock, and does not wait for the peer's close_notify.  If a
     * writer is stuck (the peer stopped reading), close_notify is skipped
     * after CLOSE_LOCK_TIMEOUT and the stream is closed anyway, which also
     * unblocks the reader and the writer.
     */
    void close() throws IOException {
        boolean locked = false;
        try {
            locked = writeLock.tryLock(CLOSE_LOCK_TIMEOUT, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        try {
            if(locked && handshakeDone && !engine.isOutboundDone()) {
                flush();
                engine.closeOutbound();
                runHandshake(false);
            }
        } finally {
            if(locked) {
                writeLock.unlock();
            }
            output.close();
        }
    }

    /* Called with writeLock held. */
    private void flush() throws IOException {
        myNetworkBuffer.flip();
        networkWriteBuffer(myNetworkBuffer);
        myNetworkBuffer.compact();
    }


    /*
     * Process what the engine asks for until it asks for nothing more.
     * NEED_UNWRAP is only acted on during the initial handshake
     * (canUnwrap); afterwards the reading thread unwraps handshake records
     * along with application data.  NEED_WRAP takes writeLock.
     */
    private boolean runHandshake(boolean canUnwrap) throws IOException {
        boolean handshakeRan = false;
        while(true) {
            if(!processHandshake(canUnwrap)) {
                return handshakeRan;
            } else {
                handshakeRan = true;
            }
        }
    }

    private boolean processHandshake(boolean canUnwrap) throws IOException {
        final HandshakeStatus hs = engine.getHandshakeStatus();
        logger.debug("processHandshake() hs = "+ hs);
        switch(hs) {
        case NEED_TASK:
            synchronousRunDelegatedTasks();
            return processHandshake(canUnwrap);

        case NEED_UNWRAP:
            if(!canUnwrap) {
                return false;
            }
            return handshakeUnwrap();

        case NEED_WRAP:
            writeLock.lock();
            try {
                return handshakeWrap();
            } finally {
                writeLock.unlock();
            }

        default:
            return false;
        }
    }

    private void synchronousRunDelegatedTasks() {
        logger.debug("runDelegatedTasks()");
        while(true) {
            Runnable r = engine.getDelegatedTask();
            if(r == null) {
                return;
            }
            logger.debug("Running a task: "+ r);
            r.run();
        }
    }

    /* Called with both locks held, during the initial handshake. */
    private boolean handshakeUnwrap() throws IOException {
            logger.debug("handshakeUnwrap()");

            if(!engine.isInboundDone() && peerNetworkBuffer.position() == 0) {
                    if(networkReadBuffer(peerNetworkBuffer) < 0) {
                            return false;
                    }
            }
            peerNetworkBuffer.flip();
            final SSLEngineResult result = engine.unwrap(peerNetworkBuffer, peerApplicationBuffer);
            peerNetworkBuffer.compact();
            logResult(result);

            if(result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                    handshakeFinished();
            }
            switch(result.getStatus()) {

            case CLOSED:
                    if(engine.isOutboundDone()) {
                            output.close();
                    }
                    return false;
            case OK:
                    return true;
            case BUFFER_UNDERFLOW:
                    if(networkReadBuffer(peerNetworkBuffer) < 0) {
                            return false;
                    }
                    return true;
            default:
                    return false;
            }
    }

    /* Called with writeLock held. */
    private boolean handshakeWrap() throws IOException {
        logger.debug("handshakeWrap()");
        // Handshake messages only: application data is wrapped by write().
        final SSLEngineResult result = engine.wrap(emptyBuffer, myNetworkBuffer);
        logResult(result);

        if(result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
            handshakeFinished();
        }

        if(result.getStatus() == Status.CLOSED) {
            try {
                flush();
            } catch (SocketException e) {
                e.printStackTrace();
            }
        } else {
            flush();
        }

        switch(result.getStatus()) {
        case CLOSED:
            if(engine.isOutboundDone()) {
                output.close();
            }
            return false;

        case OK:
            return true;

        default:
            return false;

        }
    }

    private void logResult(SSLEngineResult result) {
        logger.debug("Result status="+result.getStatus() + " hss="+ result.getHandshakeStatus() + " consumed = "+ result.bytesConsumed() + " produced = "+ result.bytesProduced());
    }

    private void handshakeFinished() {
        if(handshakeCallback != null) {
            handshakeCallback.handshakeCompleted();
        }
    }

    private void networkWriteBuffer(ByteBuffer buffer) throws IOException {
        final byte[] bs = buffer.array();
        final int off = buffer.position();
        final int len = buffer.limit() - off;
        logger.debug("networkWriteBuffer(b, "+ off + ", "+ len +")");
        output.write(bs, off, len);
        output.flush();
        buffer.position(buffer.limit());
    }

    private int networkReadBuffer(ByteBuffer buffer) throws IOException {
        final byte[] bs = buffer.array();
        final int off = buffer.position();
        final int len = buffer.limit() - off;

        final int n = input.read(bs, off, len);
        if(n != -1) {
            buffer.position(off + n);
        }
        logger.debug("networkReadBuffer(b, "+ off +", "+ len +") = "+ n);
        return n;
    }
}