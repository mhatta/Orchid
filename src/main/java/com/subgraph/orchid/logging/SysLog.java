package com.subgraph.orchid.logging;

public class SysLog {
    public static SysLog EMERGENCY = new SysLog(0, "EMERGENCY");
    public static SysLog ALERT = new SysLog(1, "ALERT");
    public static SysLog CRITICAL = new SysLog(2, "CRITICAL");
    public static SysLog ERROR = new SysLog(3, "ERROR");
    public static SysLog WARNING = new SysLog(4, "WARNING");
    public static SysLog NOTICE = new SysLog(5, "NOTICE");
    public static SysLog INFORMATIONAL = new SysLog(6, "INFORMATIONAL");
    public static SysLog DEBUG = new SysLog(7, "DEBUG");
    
    private final Integer value;
    private final String severity;
    
    private SysLog(Integer value, String severity){
        this.value = value;
        this.severity = severity;
    }

    public Integer getValue() {
        return value;
    }

    public String getSeverity() {
        return severity;
    }
    
    /**
     * Look up a level by name, case insensitively.  Accepts the severity names
     * ("DEBUG", "INFORMATIONAL", "NOTICE", "WARNING", "ERROR", ...) and the
     * common short forms "INFO" and "WARN".
     *
     * @return The level, or null if the name is not recognized.
     */
    public static SysLog forName(String name){
        if(name == null){
            return null;
        }
        final String n = name.trim().toUpperCase(java.util.Locale.ROOT);
        if(n.equals("INFO")){
            return INFORMATIONAL;
        }
        if(n.equals("WARN")){
            return WARNING;
        }
        for(SysLog level: new SysLog[] { EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFORMATIONAL, DEBUG }){
            if(level.getSeverity().equals(n)){
                return level;
            }
        }
        return null;
    }

    public Boolean isGreaterOrEqual(SysLog other){
        if(this.value!=null && other!=null && other.getValue()!=null){
            return this.value<=other.value;
        } else{
            return false;
        }
    }
}
