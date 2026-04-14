package src;

import java.time.LocalDateTime;

public class LogEntry {
    public final String ip;
    public final String ident;
    public final String user;
    public final String datetime;
    public final String method;
    public final String path;
    public final int status;

    public LogEntry(String ip, LocalDateTime timestamp, String method, String url, int statusCode, String userAgent) {
        this.ip = ip;
        this.ident = timestamp.toString();
        this.user = userAgent;
        this.datetime = timestamp.toString();
        this.method = method;
        this.path = url;
        this.status = statusCode;
    }

    public String getIp() {
        return this.ip;
    }

    public String getIdent() {
        return this.ident;
    }

    public String getUser() {
        return this.user;
    }

    public String getDatetime() {
        return this.datetime;
    }

    public String getMethod() {
        return this.method;
    }

    public String getPath() {
        return this.path;
    }

    public int getStatus() {
        return this.status;
    }
}
