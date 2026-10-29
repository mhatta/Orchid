package com.subgraph.orchid.logging;

/**
 * Where Orchid's log messages go.  The default writes them to
 * <code>System.out</code>; an Android application can send them to
 * <code>android.util.Log</code> instead, for example:
 *
 * <pre>
 * Logger.setHandler(new LogHandler() {
 *     public void log(SysLog level, String name, String message, Throwable throwable) {
 *         if(level.isGreaterOrEqual(SysLog.ERROR)) {
 *             android.util.Log.e("Orchid", name +": "+ message, throwable);
 *         } else if(level.isGreaterOrEqual(SysLog.WARNING)) {
 *             android.util.Log.w("Orchid", name +": "+ message, throwable);
 *         } else if(level.isGreaterOrEqual(SysLog.INFORMATIONAL)) {
 *             android.util.Log.i("Orchid", name +": "+ message, throwable);
 *         } else {
 *             android.util.Log.d("Orchid", name +": "+ message, throwable);
 *         }
 *     }
 * });
 * </pre>
 *
 * Only messages at or above
 * {@link com.subgraph.orchid.ApplicationProperties#getLoggingThreshold()}
 * are passed on.  The handler is called from many threads at once.  An
 * exception it throws is ignored.
 */
public interface LogHandler {
    /**
     * @param level one of the {@link SysLog} constants
     * @param name the simple name of the class that logs
     * @param message the message (never null)
     * @param throwable the exception logged with it, or null
     */
    void log(SysLog level, String name, String message, Throwable throwable);
}
