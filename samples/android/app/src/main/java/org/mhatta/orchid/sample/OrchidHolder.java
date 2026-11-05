package org.mhatta.orchid.sample;

import java.io.File;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.util.Log;

import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorInitializationListener;
import com.subgraph.orchid.logging.LogHandler;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.logging.SysLog;

/**
 * One TorClient for the whole process, started once and kept running.
 *
 * What an app that embeds Orchid has to do on Android:
 * <ul>
 * <li>set the data directory, under getNoBackupFilesDir() (the default,
 *     ~/.orchid, does not exist on Android);</li>
 * <li>start Orchid off the main thread (start() and waitUntilReady() block);</li>
 * <li>send Orchid's log to logcat;</li>
 * <li>call notifyNetworkChanged() when the device changes networks.</li>
 * </ul>
 */
final class OrchidHolder {
    interface Listener {
        void progress(String message, int percent);
        void ready();
        void failed(Throwable t);
    }

    private static final String TAG = "Orchid";
    private static OrchidHolder instance;

    private final TorClient client;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<Listener>();
    private volatile boolean ready;
    private volatile Throwable failure;

    static synchronized OrchidHolder get(Context context) {
        if(instance == null) {
            instance = new OrchidHolder(context.getApplicationContext());
        }
        return instance;
    }

    private OrchidHolder(Context context) {
        Logger.setHandler(new LogHandler() {
            public void log(SysLog level, String name, String message, Throwable throwable) {
                final String text = name + ": " + message;
                if(level.isGreaterOrEqual(SysLog.ERROR)) {
                    Log.e(TAG, text, throwable);
                } else if(level.isGreaterOrEqual(SysLog.WARNING)) {
                    Log.w(TAG, text, throwable);
                } else if(level.isGreaterOrEqual(SysLog.INFORMATIONAL)) {
                    Log.i(TAG, text, throwable);
                } else {
                    Log.d(TAG, text, throwable);
                }
            }
        });

        client = new TorClient();
        final TorConfig config = client.getConfig();
        config.setDataDirectory(new File(context.getNoBackupFilesDir(), "orchid"));

        client.addInitializationListener(new TorInitializationListener() {
            public void initializationProgress(String message, int percent) {
                for(Listener l: listeners) {
                    l.progress(message, percent);
                }
            }

            public void initializationCompleted() {
                ready = true;
                for(Listener l: listeners) {
                    l.ready();
                }
            }
        });

        executor.execute(new Runnable() {
            public void run() {
                try {
                    client.start();
                } catch(RuntimeException e) {
                    failure = e;
                    for(Listener l: listeners) {
                        l.failed(e);
                    }
                }
            }
        });

        watchNetwork(context);
    }

    /*
     * Tell Orchid when the default network changes (Wi-Fi to mobile data,
     * back online).  The callback also fires once at registration, for the
     * network in use; that one is not a change.
     */
    private void watchNetwork(Context context) {
        final ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
            private Network current;

            @Override
            public void onAvailable(Network network) {
                final boolean changed = current != null && !current.equals(network);
                current = network;
                if(changed && ready) {
                    Log.i(TAG, "default network changed");
                    client.notifyNetworkChanged();
                }
            }
        });
    }

    TorClient client() {
        return client;
    }

    boolean isReady() {
        return ready;
    }

    /** Add a listener; it is told at once if Orchid is already ready, or has failed. */
    void addListener(Listener l) {
        listeners.add(l);
        if(ready) {
            l.ready();
        } else if(failure != null) {
            l.failed(failure);
        }
    }

    void removeListener(Listener l) {
        listeners.remove(l);
    }

    ExecutorService executor() {
        return executor;
    }
}
