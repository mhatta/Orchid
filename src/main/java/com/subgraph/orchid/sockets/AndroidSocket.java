package com.subgraph.orchid.sockets;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;

/**
 * The Socket that OrchidSocketFactory returns on Android.
 *
 * It connects through its OrchidSocketImpl directly, and reports the
 * connection state through {@link #isConnected()}, which java.net.Socket
 * consults before handing out its streams.  Earlier versions set the private
 * field <code>isConnected</code> of java.net.Socket by reflection instead.
 * Since Android 9 such access to non-SDK members is restricted and may be
 * refused, after which the socket looked unconnected for good; it was also
 * needed only by the Socket implementation of Android 6 and older, which
 * read the field directly.
 */
public class AndroidSocket extends Socket {
    private final OrchidSocketImpl impl;
    private final Object lock = new Object();
    private boolean isSocketConnected;

    AndroidSocket(OrchidSocketImpl impl) throws SocketException {
        super(impl);
        this.impl = impl;
    }

    @Override
    public void connect(SocketAddress endpoint) throws IOException {
        connect(endpoint, 0);
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException {
        synchronized(lock) {
            if(isSocketConnected) {
                throw new SocketException("Already connected");
            }
            try {
                impl.connect(endpoint, timeout);
                isSocketConnected = true;
            } catch(IOException e) {
                impl.close();
                throw e;
            }
        }
    }

    @Override
    public boolean isConnected() {
        synchronized(lock) {
            return isSocketConnected;
        }
    }
}
