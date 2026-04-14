package src.detectors;

import src.LogEntry;
import src.LogParser;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.*;

public class DDoS extends Detector {

    public DDoS() {
        super("DDoS");
    }

    private LocalDateTime parseDatetime(String date) {
        try {
            return ZonedDateTime.parse(date, LogParser.getDateTimeFormatter()).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
        }  catch (Exception ignored) {}
        try {
            return LocalDateTime.parse(date);
        } catch (Exception ignored) {}
        throw new IllegalArgumentException("Format de date inconnu : " + date);
    };

    @Override
    public List<DetectionAlert> detect(List<LogEntry> entries) {
        List<DetectionAlert> detectionAlerts = new ArrayList<>();
        if (entries.isEmpty()) {
            return detectionAlerts;
        }
        List<LocalDateTime> dates = new ArrayList<>();
        for (LogEntry entry : entries) {
            dates.add(parseDatetime(entry.getDatetime()));
        }
        dates.sort(LocalDateTime::compareTo);
        LocalDateTime first = dates.get(0);
        LocalDateTime last = dates.get(entries.size() - 1);
        double totalSeconds = Math.max(1, Duration.between(first, last).toSeconds());
        double totalAverage = entries.size() / totalSeconds;
        Map<String, List<LocalDateTime>> ipLogs = new HashMap<>();
        for (int i = 0; i < entries.size(); i++) {
            String ip = entries.get(i).getIp();
            LocalDateTime date = dates.get(i);
            ipLogs.computeIfAbsent(ip, k -> new ArrayList<>()).add(date);
        }
        for (var entry : ipLogs.entrySet()) {
            String ip = entry.getKey();
            List<LocalDateTime> times = entry.getValue();
            times.sort(LocalDateTime::compareTo);
            int left = 0;
            for (int right = 0; right < times.size(); right++) {
                while (Duration.between(times.get(left), times.get(right)).toSeconds() > 10) {
                    left++;
                }
                int window = right - left + 1;
                double windowRate = window / 10.0;
                if (windowRate > totalAverage * 10) {
                    detectionAlerts.add(new DetectionAlert(ip, "Débit anormal : " + windowRate + " req/s (moyenne globale = " + totalAverage + ")"));
                    break;
                }
            }
        }
        if (entries.size() / totalSeconds > totalAverage * 50) {
            detectionAlerts.add(new DetectionAlert("GLOBAL", "CRITICAL : Volume global > 50x la moyenne (" + totalAverage + " req/s)"));
        }
        return detectionAlerts;
    }
}