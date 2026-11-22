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
    /*
     * Tries of the request, each over new circuits (another isolation
     * key), so usually through another exit relay.  An exit that ends the
     * stream at once (the TLS handshake "did not complete") fails one try,
     * not the test: the request has only one route, so OkHttp itself does
     * not try again.  A failure on every try still fails the test.
     */
    private static final int FETCH_TRIES = 3;

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

        final String answer = fetchWithTries(orchid.client());
        Log.i(TorCheck.TAG, "check.torproject.org: " + answer);
        assertTrue("not through Tor: " + answer, TorCheck.isTor(answer));

        refusesCertificateForAnotherName(orchid.client());
        platformTlsOverTor(orchid.client());
    }

    private static String fetchWithTries(TorClient tor) throws IOException {
        IOException last = null;
        for (int i = 1; i <= FETCH_TRIES; i++) {
            try {
                return TorCheck.fetch(tor, "orchid-sample-test-" + i);
            } catch (IOException e) {
                // The test report keeps only the first line; logcat.txt (the
                // CI artifact) gets the causes, e.g. "Trust anchor for
                // certification path not found", and Orchid's log says why
                // the exit relay ended the stream.
                Log.e(TorCheck.TAG, "request through Tor failed (try " + i + " of " + FETCH_TRIES + ")", e);
                if (!isRouteProblem(e)) {
                    throw e;
                }
                last = e;
            }
        }
        throw last;
    }

    /*
     * Failures that another circuit can cure: the stream ended or timed
     * out, or could not be opened.  Not a certificate or host name problem,
     * which another exit would not change.
     */
    private static boolean isRouteProblem(IOException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof java.security.cert.CertificateException
                    || t instanceof javax.net.ssl.SSLPeerUnverifiedException) {
                return false;
            }
        }
        return true;
    }

    /*
     * Not a check, a measurement: does the platform's own SSLSocket (not
     * AndroidSSLSocketFactory) complete a handshake over a Tor stream on
     * this API level?  On API 24 it does not ("Socket closed").  The result
     * goes to logcat (logcat.txt in the CI artifact) and never fails the
     * test; the trust manager is the sample's, with the extra roots, so
     * that a missing root does not hide the answer.
     */
    private static void platformTlsOverTor(TorClient tor) throws Exception {
        final String host = "check.torproject.org";
        final String api = "API " + android.os.Build.VERSION.SDK_INT;
        final Socket raw;
        try {
            raw = tor.getSocketFactory("orchid-sample-platform-tls").createSocket(host, 443);
        } catch (IOException e) {
            Log.w(TorCheck.TAG, "platform TLS over Tor on " + api + ": not tested, cannot reach " + host, e);
            return;
        }
        final SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new TrustManager[] { TorCheck.platformTrustManager() }, null);
        final javax.net.ssl.SSLSocket s =
                (javax.net.ssl.SSLSocket) tls.getSocketFactory().createSocket(raw, host, 443, true);
        try {
            s.startHandshake();
            Log.i(TorCheck.TAG, "platform TLS over Tor on " + api + ": works ("
                    + s.getSession().getProtocol() + ", " + s.getSession().getCipherSuite() + ")");
        } catch (IOException e) {
            Log.i(TorCheck.TAG, "platform TLS over Tor on " + api + ": fails (" + e + ")");
        } finally {
            try {
                s.close();
            } catch (IOException e) {
                // closing a failed socket
            }
        }
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
