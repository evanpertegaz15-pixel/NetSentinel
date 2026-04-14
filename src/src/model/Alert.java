package src.src.model;

import java.time.LocalDateTime;

public class Alert {
    private String ip;
    private LocalDateTime timestamp;
    private String threatType;
    private Severity severity;
    private long count;

    public Alert(String ip, LocalDateTime timestamp, String threatType, Severity severity, long count) {
        this.ip = ip;
        this.timestamp = timestamp;
        this.threatType = threatType;
        this.severity = severity;
        this.count = count;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getThreatType() {
        return threatType;
    }

    public void setThreatType(String threatType) {
        this.threatType = threatType;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public long getCount() {
        return count;
    }

    public void setCount(long count) {
        this.count = count;
    }

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }
}