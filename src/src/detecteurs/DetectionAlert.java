package src.detecteurs;

public class DetectionAlert {
    private final String ip;
    private final String message;

    public DetectionAlert(String ip, String message) {
        this.ip = ip;
        this.message = message;
    }

    public String getIp() {
        return ip;
    }

    public String getMessage() {
        return message;
    }
}
