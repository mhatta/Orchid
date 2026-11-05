package org.mhatta.orchid.sample;

import java.io.IOException;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Starts Orchid and, once it is ready, fetches
 * https://check.torproject.org/api/ip through it with OkHttp.  The result
 * is shown and logged (logcat tag OrchidSample).
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

    private void fetch() {
        try {
            final String result = TorCheck.fetch(orchid.client());
            Log.i(TorCheck.TAG, "check.torproject.org: " + result);
            append("check.torproject.org: " + result);
        } catch(IOException e) {
            Log.w(TorCheck.TAG, "Request failed", e);
            append("Request failed: " + e);
        }
    }
}
