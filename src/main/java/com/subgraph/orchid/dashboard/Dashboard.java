package com.subgraph.orchid.dashboard;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;

import com.subgraph.orchid.Threading;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.logging.Logger;
import com.subgraph.orchid.misc.GuardedBy;

/**
 * A debugging utility which displays continuously updated information about the internal state
 * of various components to clients which connect to a network port listening on localhost.
 */
public class Dashboard implements DashboardRenderable, DashboardRenderer {
    private static final Logger logger = Logger.getInstance(Dashboard.class);
	
    private final static String DASHBOARD_PORT_PROPERTY = "com.subgraph.orchid.dashboard.port";

    private final static int DEFAULT_LISTENING_PORT = 12345;
    private final static int DEFAULT_FLAGS = DASHBOARD_CIRCUITS | DASHBOARD_STREAMS;
    private final static IPv4Address LOCALHOST = IPv4Address.createFromString("127.0.0.1");

    @GuardedBy("this") private int listeningPort;
    @GuardedBy("this") private int flags = DEFAULT_FLAGS;
    @GuardedBy("this") private ServerSocket listeningSocket;
    @GuardedBy("this") private boolean isListening;

    private final List<DashboardRenderable> renderables;
    private final Executor executor;

    public Dashboard() {
        renderables = new CopyOnWriteArrayList<DashboardRenderable>();
        renderables.add(this);
        executor = Threading.newPool("Dashboard worker");
        listeningPort = chooseListeningPort();
    }

    private static int chooseListeningPort() {
        final String dbPort = System.getProperty(DASHBOARD_PORT_PROPERTY);
        final int port = parsePortProperty(dbPort);
        if(port > 0 && port <= 0xFFFF) {
            return port;
        } else if(dbPort != null) {
            logger.warn(DASHBOARD_PORT_PROPERTY + " was not a valid port value: "+ dbPort);
        }
        return DEFAULT_LISTENING_PORT;
    }

    private static int parsePortProperty(String dbPort) {
        if(dbPort == null) {
            return -1;
        }
        try {
            return Integer.parseInt(dbPort);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    public void addRenderables(Object...objects) {
        for(Object ob: objects) {
            if(ob instanceof DashboardRenderable) {
                renderables.add((DashboardRenderable) ob);
            }
        }
    }

    public void addRenderable(DashboardRenderable renderable) {
        renderables.add(renderable);
    }

    public synchronized void enableFlag(int flag) {
        flags |= flag;
    }

    public synchronized void disableFlag(int flag) {
        flags &= ~flag;
    }


    public synchronized boolean isEnabled(int f) {
        return (flags & f) != 0;
    }

    public synchronized void setListeningPort(int port) {
        if(port != listeningPort) {
            listeningPort = port;
            if(isListening) {
                stopListening();
                startListening();
            }
        }
    }

    public boolean isEnabledByProperty() {
        return System.getProperty(DASHBOARD_PORT_PROPERTY) != null;
    }

    private final static String ALLOW_ON_ANDROID_PROPERTY = "com.subgraph.orchid.dashboard.allowOnAndroid";

    /*
     * The dashboard has no authentication and shows the entry guards, the
     * circuits and the streams.  On a desktop only the local user's programs
     * can usually reach 127.0.0.1, but on Android every app on the device
     * can, so another app could watch how the user's traffic is routed.  The
     * dashboard is a debugging tool; on Android it is not started unless
     * the system property com.subgraph.orchid.dashboard.allowOnAndroid is
     * "true", for a debug build.
     */
    static boolean mayListen(String vmName, String allowOnAndroid) {
        final boolean android = "Dalvik".equals(vmName);
        return !android || "true".equals(allowOnAndroid);
    }

    public synchronized void startListening() {
        if(isListening) {
            return;
        }
        if(!mayListen(System.getProperty("java.vm.name"), System.getProperty(ALLOW_ON_ANDROID_PROPERTY))) {
            logger.warn("Not starting the dashboard: on Android every app could connect to it.  Set "
                    + ALLOW_ON_ANDROID_PROPERTY +"=true to start it anyway in a debug build.");
            return;
        }
        try {
            listeningSocket = new ServerSocket(listeningPort, 50, LOCALHOST.toInetAddress());
            isListening = true;
            logger.info("Dashboard listening on "+ LOCALHOST + ":"+ listeningPort);
            executor.execute(createAcceptLoopRunnable(listeningSocket));
        } catch (IOException e) {
            logger.warn("Failed to create listening Dashboard socket on port "+ listeningPort +": "+ e);
        }
    }

    public synchronized void stopListening() {
        if(!isListening) {
            return;
        }
        if(listeningSocket != null) {
            closeQuietly(listeningSocket);
            listeningSocket = null;
        }
        isListening = false;
    }

    public synchronized boolean isListening() {
        return isListening;
    }

    private Runnable createAcceptLoopRunnable(final ServerSocket ss) {
        return new Runnable() {
            public void run() {
                acceptConnections(ss);
            }
        };
    }

    private void acceptConnections(ServerSocket ss) {
        while(true) {
            try {
                Socket s = ss.accept();
                executor.execute(new DashboardConnection(this, s));
            } catch (IOException e) {
                if(!ss.isClosed()) {
                    logger.warn("IOException on dashboard server socket: "+ e);
                }
                stopListening();
                return;
            }
        }
    }

    void renderAll(PrintWriter writer) throws IOException {
        final int fs;
        synchronized (this) {
            fs = flags;
        }

        for(DashboardRenderable dr: renderables) {
            dr.dashboardRender(this, writer, fs);
        }
    }

    private void closeQuietly(ServerSocket s) {
        try {
            s.close();
        } catch (IOException e) { 
            //swallow
        }
    }

    @Override
    public void dashboardRender(DashboardRenderer renderer, PrintWriter writer, int flags) {
        writer.println("[Dashboard]");
        writer.println();
    }

    @Override
    public void renderComponent(PrintWriter writer, int flags, Object component) throws IOException {
        if(!(component instanceof DashboardRenderable)) {
            return;
        }
        final DashboardRenderable renderable = (DashboardRenderable) component;
        renderable.dashboardRender(this, writer, flags);
    }
}
