package org.mhatta.orchid.sample;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.List;

import com.subgraph.orchid.TorClient;
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
     * Do not use OkHttp's proxy(new Proxy(SOCKS, ...)) on Android: the
     * platform's SOCKS client speaks SOCKS 4 only, without host names.
     */
    static OkHttpClient httpClient(TorClient tor) {
        return new OkHttpClient.Builder()
                .socketFactory(tor.getSocketFactory("orchid-sample"))
                .dns(new Dns() {
                    public List<InetAddress> lookup(String hostname) {
                        return Collections.singletonList(OrchidSocketFactory.unresolvedAddress(hostname));
                    }
                })
                .build();
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
