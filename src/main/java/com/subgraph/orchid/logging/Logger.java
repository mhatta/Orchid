package com.subgraph.orchid.logging;

import com.subgraph.orchid.ApplicationProperties;

/**
 * Orchid's logger.  Messages at or above
 * {@link ApplicationProperties#getLoggingThreshold()} go to the
 * {@link LogHandler} set with {@link #setHandler(LogHandler)}, by default
 * {@link ConsoleLogHandler} (<code>System.out</code>).
 */
public class Logger {
    private static volatile LogHandler handler = ConsoleLogHandler.INSTANCE;

    private final String name;
    
    private Logger(Class<?> aClass){
        this.name = aClass.getSimpleName();
    }
    
    public static Logger getInstance(Class<?> aClass){
        return new Logger(aClass);
    }

    /**
     * Send all log messages to the given handler, or to
     * {@link ConsoleLogHandler} again if it is null.
     */
    public static void setHandler(LogHandler newHandler){
        handler = (newHandler != null) ? newHandler : ConsoleLogHandler.INSTANCE;
    }

    public static LogHandler getHandler(){
        return handler;
    }
    
    private static boolean shouldLog(SysLog level){
        return level.isGreaterOrEqual(ApplicationProperties.getLoggingThreshold());
    }

    /** Whether debug messages are logged, to skip building costly ones. */
    public boolean isDebugEnabled(){
        return shouldLog(SysLog.DEBUG);
    }
    
    public void debug(Object message){
        debug(message, null);
    }
    
    public void debug(Object message, Throwable throwable){
        log(SysLog.DEBUG, message, throwable);
    }
    
    public void warn(Object message){
        warn(message, null);
    }
    
    public void warn(Object message, Throwable throwable){
        log(SysLog.WARNING, message, throwable);
    }
    
    public void info(Object message){
        info(message, null);
    }
    
    public void info(Object message, Throwable throwable){
        log(SysLog.INFORMATIONAL, message, throwable);
    }
    
    public void error(Object message){
        error(message, null);
    }
    
    public void error(Object message, Throwable throwable){
        log(SysLog.ERROR, message, throwable);
    }
    
    public void fatal(Object message){
        fatal(message, null);
    }
    
    public void fatal(Object message, Throwable throwable){
        log(SysLog.EMERGENCY, message, throwable);
    }

    private void log(SysLog level, Object message, Throwable throwable){
        if(!shouldLog(level)){
            return;
        }
        try {
            handler.log(level, name, (message == null) ? "" : message.toString(), throwable);
        } catch(RuntimeException e) {
            // A failing handler must not break Orchid.
        }
    }
}
