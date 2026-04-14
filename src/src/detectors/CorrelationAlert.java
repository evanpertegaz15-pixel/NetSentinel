package src.detectors;

import java.util.*;

public class CorrelationAlert {
    public enum Severity {LOW, MEDIUM, HIGH, CRITICAL}

    public Map<String, Severity> correlate(List<DetectionAlert> detectionAlerts) {
        Map<String, Set<String>> ipDetectors = new HashMap<>();
        for (DetectionAlert detectionAlert : detectionAlerts) {
            ipDetectors.computeIfAbsent(detectionAlert.getIp(), k -> new HashSet<>()).add(detectionAlert.getDetector());
        }
        Map<String, Severity> detectedSeverities = new HashMap<>();
        for (var entry : ipDetectors.entrySet()) {
            String ip = entry.getKey();
            int count = entry.getValue().size();
            Severity severity;
            if (count >= 3)  {
                severity = Severity.CRITICAL;
            } else if (count == 2)  {
                severity = Severity.HIGH;
            } else if (count == 1)  {
                severity = Severity.MEDIUM;
            } else {
                severity = Severity.LOW;
            }
            detectedSeverities.put(ip, severity);
        }
        return detectedSeverities;
    };
}
