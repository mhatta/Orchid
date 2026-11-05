package org.mhatta.orchid.sample;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Test;
import org.junit.runner.RunWith;

import android.content.Context;
import android.util.Log;

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

        final String answer = TorCheck.fetch(orchid.client());
        Log.i(TorCheck.TAG, "check.torproject.org: " + answer);
        assertTrue("not through Tor: " + answer, TorCheck.isTor(answer));
    }
}
