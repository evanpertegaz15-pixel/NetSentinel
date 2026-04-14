package src.detectors;

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

    public abstract List<DetectionAlert> detect(List<LogEntry> entries);
}
