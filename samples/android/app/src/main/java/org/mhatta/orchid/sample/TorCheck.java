package org.mhatta.orchid.sample;

import java.io.IOException;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.sockets.AndroidSSLSocketFactory;
import com.subgraph.orchid.sockets.OrchidSocketFactory;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Ask https://check.torproject.org/api/ip, through Orchid, whether the
 * request came from Tor.  Used by the activity and by the instrumented
 * test.
 */
final class TorCheck {
    static final String TAG = "OrchidSample";
    static final String URL = "https://check.torproject.org/api/ip";

    private TorCheck() {}

    /*
     * OkHttp through Orchid, without DNS leaks:
     *
     * - socketFactory: the connections go through Tor.  The isolation key
     *   keeps this app's circuits apart from streams with other keys.
     * - dns: OkHttp resolves host names itself before it connects, which
     *   would ask the device's DNS.  unresolvedAddress() returns a
     *   placeholder instead, and the exit relay resolves the name.
     *
     * - sslSocketFactory: TLS runs over the Tor stream through an SSLEngine
     *   (AndroidSSLSocketFactory).  The platform's own SSLSocket wraps the
     *   socket's file descriptor, and a socket through Orchid has none: on
     *   older releases (seen on Android 7.0, API 24) the handshake fails
     *   with "SocketException: Socket closed".  The device's trusted CAs are
     *   used, and OkHttp still checks the host name.
     *
     * Do not use OkHttp's proxy(new Proxy(SOCKS, ...)) on Android: the
     * platform's SOCKS client speaks SOCKS 4 only, without host names.
     */
    static OkHttpClient httpClient(TorClient tor) throws IOException {
        final X509TrustManager trustManager = platformTrustManager();
        final SSLContext tls;
        try {
            tls = SSLContext.getInstance("TLS");
            tls.init(null, new TrustManager[] { trustManager }, null);
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot set up TLS", e);
        }
        return new OkHttpClient.Builder()
                .socketFactory(tor.getSocketFactory("orchid-sample"))
                .sslSocketFactory(new AndroidSSLSocketFactory(tls), trustManager)
                .dns(new Dns() {
                    public List<InetAddress> lookup(String hostname) {
                        return Collections.singletonList(OrchidSocketFactory.unresolvedAddress(hostname));
                    }
                })
                .build();
    }

    /** The trust manager of the device's trusted CAs. */
    static X509TrustManager platformTrustManager() throws IOException {
        try {
            final TrustManagerFactory factory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager tm : factory.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    return (X509TrustManager) tm;
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot load the trusted CAs", e);
        }
        throw new IOException("no X509TrustManager on this device");
    }

    /** "200 {...}": the status and the body of the answer. */
    static String fetch(TorClient tor) throws IOException {
        final Request request = new Request.Builder().url(URL).build();
        try (Response response = httpClient(tor).newCall(request).execute()) {
            return response.code() + " " + response.body().string();
        }
    }

    /** Whether an answer of {@link #fetch} says the request came through Tor. */
    static boolean isTor(String answer) {
        return answer.startsWith("200 ") && answer.replace(" ", "").contains("\"IsTor\":true");
    }
}
