package src.detecteurs;

import src.LogEntry;
import java.util.List;

public abstract class Detector {
    private final String name;

    protected Detector(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    protected boolean isErrorCode(int code) {
        return code == 401 || code == 403 || code == 404;
    }

    public abstract List<DetectionAlert> detect(List<LogEntry> entries);
}
