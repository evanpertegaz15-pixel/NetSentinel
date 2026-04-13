public class LogEntry {
    public final String ip;
    public final String ident;
    public final String user;
    public final String datetime;
    public final String method;
    public final String path;
    public final String protocol;
    public final int status;
    public final long size;
    public final String referrer;
    public final String agent;

    public LogEntry(String ip, String indent, String user, String datetime, String method, String path, String protocol, int status, long size, String referrer, String agent) {
        this.ip = ip;
        this.ident = indent;
        this.user = user;
        this.datetime = datetime;
        this.method = method;
        this.path = path;
        this.protocol = protocol;
        this.status = status;
        this.size = size;
        this.referrer = referrer;
        this.agent = agent;
    }
}
