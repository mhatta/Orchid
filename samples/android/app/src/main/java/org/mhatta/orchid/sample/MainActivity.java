package org.mhatta.orchid.sample;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;
import java.util.List;

import android.app.Activity;
import android.os.Bundle;
import android.widget.ScrollView;
import android.widget.TextView;

import com.subgraph.orchid.sockets.OrchidSocketFactory;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Starts Orchid and, once it is ready, fetches
 * https://check.torproject.org/api/ip through it with OkHttp.
 */
public class MainActivity extends Activity implements OrchidHolder.Listener {
    private TextView text;
    private OrchidHolder orchid;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        text = new TextView(this);
        text.setPadding(32, 32, 32, 32);
        final ScrollView scroll = new ScrollView(this);
        scroll.addView(text);
        setContentView(scroll);

        orchid = OrchidHolder.get(this);
        append("Starting Orchid...");
        orchid.addListener(this);
    }

    @Override
    protected void onDestroy() {
        orchid.removeListener(this);
        super.onDestroy();
    }

    private void append(final String line) {
        runOnUiThread(new Runnable() {
            public void run() {
                text.append(line + "\n");
            }
        });
    }

    public void progress(String message, int percent) {
        append(percent + "% " + message);
    }

    public void failed(Throwable t) {
        append("Orchid failed to start: " + t);
    }

    public void ready() {
        append("Orchid is ready.");
        orchid.executor().execute(new Runnable() {
            public void run() {
                fetch();
            }
        });
    }

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
    private void fetch() {
        final OkHttpClient http = new OkHttpClient.Builder()
                .socketFactory(orchid.client().getSocketFactory("orchid-sample"))
                .dns(new Dns() {
                    public List<InetAddress> lookup(String hostname) {
                        return Collections.singletonList(OrchidSocketFactory.unresolvedAddress(hostname));
                    }
                })
                .build();
        final Request request = new Request.Builder().url("https://check.torproject.org/api/ip").build();
        try (Response response = http.newCall(request).execute()) {
            append("check.torproject.org: " + response.code() + " " + response.body().string());
        } catch(IOException e) {
            append("Request failed: " + e);
        }
    }
}
