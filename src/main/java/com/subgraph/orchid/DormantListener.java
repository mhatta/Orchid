package com.subgraph.orchid;

/**
 * Told when a {@link TorClient} becomes dormant or wakes up, for example to
 * change the text of an Android app's foreground notification.  See
 * {@link TorClient#addDormantListener(DormantListener)}.
 *
 * @since 2.8.0
 */
public interface DormantListener {
	/**
	 * Called on one of Orchid's threads, or on the thread that asked for the
	 * change; return quickly, and do not wait on Orchid in it.  On Android,
	 * post to the main thread to update the UI.
	 *
	 * @param dormant true when the client has just become dormant, false
	 *                when it has just woken up
	 */
	void dormantStateChanged(boolean dormant);
}
