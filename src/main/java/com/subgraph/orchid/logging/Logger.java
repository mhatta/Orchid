package com.subgraph.orchid.logging;

import com.subgraph.orchid.ApplicationProperties;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class Logger {
    private static final SimpleDateFormat LOG_TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");
    private final Class aClass;
    
    private Logger(Class aClass){
        this.aClass = aClass;
    }
    
    public static Logger getInstance(Class aClass){
        return new Logger(aClass);
    }
    
    private boolean shouldLog(SysLog level){
        return level.isGreaterOrEqual(ApplicationProperties.getLoggingThreshold());
    }
    
    public void debug(Object message){
        debug(message, null);
    }
    
    public void debug(Object message, Throwable throwable){
        SysLog level = SysLog.DEBUG;
        if(shouldLog(level)){
            System.out.println(constrctLogMessage("DEBUG", message, throwable));
        }
    }
    
    public void warn(Object message){
        warn(message, null);
    }
    
    public void warn(Object message, Throwable throwable){
        SysLog level = SysLog.WARNING;
        if(shouldLog(level)){
            System.out.println(constrctLogMessage("WARN", message, throwable));
        }
    }
    
    public void info(Object message){
        info(message, null);
    }
    
    public void info(Object message, Throwable throwable){
        SysLog level = SysLog.INFORMATIONAL;
        if(shouldLog(level)){
            System.out.println(constrctLogMessage("INFO", message, throwable));
        }
    }
    
    public void error(Object message){
        error(message, null);
    }
    
    public void error(Object message, Throwable throwable){
        SysLog level = SysLog.ERROR;
        if(shouldLog(level)){
            System.out.println(constrctLogMessage("ERROR", message, throwable));
        }
    }
    
    public void fatal(Object message){
        fatal(message, null);
    }
    
    public void fatal(Object message, Throwable throwable){
        SysLog level = SysLog.EMERGENCY;
        if(shouldLog(level)){
            System.out.println(constrctLogMessage("FATAL", message, throwable));
        }
    }
    
    private String constrctLogMessage(String level, Object message, Throwable throwable){
        String timestamp = LOG_TIMESTAMP_FORMAT.format(Calendar.getInstance().getTime());
        String log = timestamp+" "+level+" - "+aClass.getSimpleName()+" - ";
        if(message!=null){
            log+=message.toString();
        }
        if(throwable!=null){
            log+=throwable.getLocalizedMessage();
        }
        return log;
    }
}