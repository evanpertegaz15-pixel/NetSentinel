package src.detectors;

public class DetectionAlert {
    private final String ip;
    private final String message;
    private final String detector;

    public DetectionAlert(String ip, String message,  String detector) {
        this.ip = ip;
        this.message = message;
        this.detector = detector;
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
}
