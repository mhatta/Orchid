package org.mhatta.orchid.sample;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;

import org.junit.Test;
import org.junit.runner.RunWith;

import android.content.Context;
import android.util.Log;

import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.sockets.AndroidSSLSocketFactory;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

/**
 * On a device or an emulator: Orchid starts, builds circuits, and a
 * request through it reaches check.torproject.org from Tor.  It needs a
 * network connection that can reach the Tor network.
 *
 * <pre>
 * cd samples/android
 * ../../gradlew connectedDebugAndroidTest
 * </pre>
 */
@RunWith(AndroidJUnit4.class)
public class TorConnectionTest {
    private static final long BOOTSTRAP_MINUTES = 5;

    @Test
    public void requestGoesThroughTor() throws Exception {
        final Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        final OrchidHolder orchid = OrchidHolder.get(context);
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
        orchid.addListener(new OrchidHolder.Listener() {
            public void progress(String message, int percent) {
                Log.i(TorCheck.TAG, percent + "% " + message);
            }

            public void ready() {
                done.countDown();
            }

            public void failed(Throwable t) {
                failure.set(t);
                done.countDown();
            }
        });

        assertTrue("Orchid was not ready after " + BOOTSTRAP_MINUTES + " minutes",
                done.await(BOOTSTRAP_MINUTES, TimeUnit.MINUTES));
        assertNull("Orchid failed to start", failure.get());

        final String answer;
        try {
            answer = TorCheck.fetch(orchid.client());
        } catch (java.io.IOException e) {
            // The test report keeps only the first line; logcat.txt (the CI
            // artifact) gets the causes, e.g. "Trust anchor for certification
            // path not found".
            Log.e(TorCheck.TAG, "request through Tor failed", e);
            throw e;
        }
        Log.i(TorCheck.TAG, "check.torproject.org: " + answer);
        assertTrue("not through Tor: " + answer, TorCheck.isTor(answer));

        refusesCertificateForAnotherName(orchid.client());
    }

    /*
     * AndroidSSLSocketFactory on its own, without OkHttp's host name check:
     * wrong.host.badssl.com serves a valid certificate for another name, and
     * the handshake must fail.  Skipped if the site cannot be reached.
     */
    private static void refusesCertificateForAnotherName(TorClient tor) throws Exception {
        final String host = "wrong.host.badssl.com";
        final Socket raw;
        try {
            raw = tor.getSocketFactory("orchid-sample-wrong-host").createSocket(host, 443);
        } catch (IOException e) {
            Log.w(TorCheck.TAG, "cannot reach " + host + "; host name check not tested", e);
            return;
        }
        final SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new TrustManager[] { TorCheck.platformTrustManager() }, null);
        final javax.net.ssl.SSLSocket s =
                (javax.net.ssl.SSLSocket) new AndroidSSLSocketFactory(tls).createSocket(raw, host, 443, true);
        try {
            s.startHandshake();
            fail("certificate of " + host + " accepted: " + s.getSession().getPeerPrincipal());
        } catch (SSLException e) {
            Log.i(TorCheck.TAG, host + " refused as it should be: " + e);
        } finally {
            s.close();
        }
    }
}
