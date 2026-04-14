package src.detectors;

import java.time.LocalDateTime;

public class DetectionAlert {
    private final String ip;
    private final String message;
    private final String detector;
    private final LocalDateTime date;

    public DetectionAlert(String ip, String message,  String detector,  LocalDateTime date) {
        this.ip = ip;
        this.message = message;
        this.detector = detector;
        this.date = date;
    }

    public String getIp() {
        return ip;
    }

    public String getMessage() {
        return message;
    }

    public String getDetector() {
        return detector;
    }

    public LocalDateTime getDate() {
        return date;
    }
}
