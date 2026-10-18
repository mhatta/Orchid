package com.subgraph.orchid.circuits.guards;

import java.util.logging.Level;

import com.subgraph.orchid.ConnectionCache;
import com.subgraph.orchid.ConnectionIOException;
import com.subgraph.orchid.GuardEntry;
import com.subgraph.orchid.Router;
import com.subgraph.orchid.logging.Logger;

public class GuardProbeTask implements Runnable{
    private static final Logger logger = Logger.getInstance(GuardProbeTask.class);
    private final ConnectionCache connectionCache;
    private final EntryGuards entryGuards;
    private final GuardEntry entry;

    public GuardProbeTask(ConnectionCache connectionCache, EntryGuards entryGuards, GuardEntry entry) {
        this.connectionCache = connectionCache;
        this.entryGuards = entryGuards;
        this.entry = entry;
    }
	
    @Override
    public void run() {
        final Router router = entry.getRouterForEntry();
        if(router == null) {
            entryGuards.probeConnectionFailed(entry);
            return;
        }
        try {
            connectionCache.getConnectionTo(router, false);
            entryGuards.probeConnectionSucceeded(entry);
            return;
        } catch (ConnectionIOException e) {
            logger.info("Failed to connect to entry guard "+ router + " : "+ e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch(Exception e) {
            logger.warn("Unexpected exception probing entry guard: "+ e, e);
        }
        entryGuards.probeConnectionFailed(entry);
    }
}
