package com.subgraph.orchid.sockets.sslengine;

import com.subgraph.orchid.logging.Logger;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketException;
import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class SSLEngineManager {
    private static final Logger logger = Logger.getInstance(SSLEngineManager.class);
	
    private final SSLEngine engine;
    private final InputStream input;
    private final OutputStream output;

    private final ByteBuffer peerApplicationBuffer;
    private final ByteBuffer peerNetworkBuffer;
    private final ByteBuffer myApplicationBuffer;
    private final ByteBuffer myNetworkBuffer;

    private final HandshakeCallbackHandler handshakeCallback;

    private boolean handshakeStarted = false;


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

    void startHandshake() throws IOException {
        logger.debug("startHandshake()");
        handshakeStarted = true;
        engine.beginHandshake();
        runHandshake();
    }

    ByteBuffer getSendBuffer() {
        return myApplicationBuffer;
    }

    ByteBuffer getRecvBuffer() {
        return peerApplicationBuffer;
    }


    int write() throws IOException {
        logger.debug("write()");
        if(!handshakeStarted) {
            startHandshake();
        }
        final int p = myApplicationBuffer.position();
        if(p == 0) {
            return 0;
        }
        myNetworkBuffer.clear();
        myApplicationBuffer.flip();
        final SSLEngineResult result = engine.wrap(myApplicationBuffer, myNetworkBuffer);
        myApplicationBuffer.compact();
        logResult(result);

        switch(result.getStatus()) {
        case BUFFER_OVERFLOW:
            throw new BufferOverflowException();
        case BUFFER_UNDERFLOW:
            throw new BufferUnderflowException();
        case CLOSED:
            throw new SSLException("SSLEngine is closed");

        case OK:
            break;
        default:
            break;
        }

        flush();
        if(runHandshake()) {
            write();
        }

        return p - myApplicationBuffer.position();

    }

    /**
     * Read application data from the peer into peerApplicationBuffer.
     *
     * Returns the number of bytes added to peerApplicationBuffer, which is
     * always more than zero, or -1 at the end of the stream.  It never
     * returns 0: callers take a read that produced nothing for the end of
     * the stream.
     *
     * TLS records are unwrapped until one of them carries application data.
     * Records without any are common: TLS 1.3 servers send NewSessionTicket
     * messages after the handshake, and a KeyUpdate may come at any time.
     * A record that has only partly arrived (BUFFER_UNDERFLOW) is completed
     * from the network.  Records already received are unwrapped before the
     * network is read again, so that data the peer has sent is never left
     * waiting in peerNetworkBuffer while we block on the socket.
     */
    int read() throws IOException {
        logger.debug("read()");
        if(!handshakeStarted) {
            startHandshake();
        }

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
                    runHandshake();
                    return (produced > 0) ? produced : -1;

                case OK:
                    // Answer whatever the record asked for (a KeyUpdate needs a reply).
                    runHandshake();
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

    void close() throws IOException {
        try {
            flush();
            if(!engine.isOutboundDone()) {
                engine.closeOutbound();
                runHandshake();
            } else if(!engine.isInboundDone()) {
                engine.closeInbound();
                runHandshake();
            }
        } finally {
            output.close();
        }
    }

    void flush() throws IOException {
        myNetworkBuffer.flip();
        networkWriteBuffer(myNetworkBuffer);
        myNetworkBuffer.compact();
    }


    private boolean runHandshake() throws IOException {
        boolean handshakeRan = false;
        while(true) {
            if(!processHandshake()) {
                return handshakeRan;
            } else {
                handshakeRan = true;
            }
        }
    }

    private boolean processHandshake() throws IOException {
        final HandshakeStatus hs = engine.getHandshakeStatus();
        logger.debug("processHandshake() hs = "+ hs);
        switch(hs) {
        case NEED_TASK:
            synchronousRunDelegatedTasks();
            return processHandshake();

        case NEED_UNWRAP:
            return handshakeUnwrap();

        case NEED_WRAP:
            return handshakeWrap();

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

    private boolean handshakeWrap() throws IOException {
        logger.debug("handshakeWrap()");
        myApplicationBuffer.flip();
        final SSLEngineResult result = engine.wrap(myApplicationBuffer, myNetworkBuffer);
        myApplicationBuffer.compact();
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