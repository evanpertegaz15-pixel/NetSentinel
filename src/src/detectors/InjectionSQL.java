package src.detectors;

import src.LogEntry;
import src.reports.Whitelist;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class InjectionSQL extends Detector {
    private static final String[] PATTERNS = {
            "' OR 1=1",
            "UNION SELECT",
            "DROP TABLE",
            "--",
            "';"
    };

    public InjectionSQL() {
        super("InjectionSQL");
    }

    @Override
    public List<DetectionAlert> detect(List<LogEntry> entries) {
        List<DetectionAlert> detectionAlerts = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (Whitelist.isWhitelisted(entry.getIp())) {
                continue;
            }
            String url = entry.getPath().toUpperCase();
            for (String pattern : PATTERNS) {
                if (url.contains(pattern.toUpperCase())) {
                    detectionAlerts.add(new DetectionAlert(entry.getIp(), "Pattern SQL suspect détecté : " + pattern, getName(), LocalDateTime.parse(entry.getDatetime())));
                }
            }
        }
        return detectionAlerts;
    }
}
