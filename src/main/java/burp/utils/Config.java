package burp.utils;

public class Config {

    public enum RedirectsMode {
        istrue, isfalse
    }

    public enum ContentTypeMode {
        不使用,urlencoded, json,xml
    }

    public enum ContentBodyMode {
        不带,带
    }

    public enum severityMode {
        info,low,medium,high,critical
    }

    public enum reqMode {
        GET,POST,RAW,PUT,OPTIONS,TRACE
    }

}
