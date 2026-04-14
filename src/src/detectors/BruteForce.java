package src.detectors;


import src.LogEntry;
import src.reports.Whitelist;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

public class BruteForce extends Detector {
    private static final int SEUIL_MEDIUM = 10;
    private static final int SEUIL_HIGH = 50;
    private static final Duration FENETRE = Duration.ofMinutes(5);

    public BruteForce() {
        super("BruteForce");
    }

    private LocalDateTime parseDatetime(LogEntry entry) {
        return LocalDateTime.parse(entry.getDatetime());
    }

    @Override
    public List<DetectionAlert> detect(List<LogEntry> logs) {
        Map<String, List<LocalDateTime>> echecsParIp = new HashMap<>();
        for (LogEntry log : logs) {
            int status = log.getStatus();
            if (status == 401 || status == 403) {
                echecsParIp.computeIfAbsent(log.getIp(), k -> new ArrayList<>())
                        .add(parseDatetime(log));
            }
        }
        List<DetectionAlert> alerts = new ArrayList<>();
        for (var entry : echecsParIp.entrySet()) {
            String ip = entry.getKey();
            if (Whitelist.isWhitelisted(ip)) {
                continue;
            }
            List<LocalDateTime> echecs = entry.getValue();
            Collections.sort(echecs);
            for (int i = 0; i < echecs.size(); i++) {
                LocalDateTime debut = echecs.get(i);
                LocalDateTime fin = debut.plus(FENETRE);
                long count = echecs.stream().filter(t -> !t.isAfter(fin)).count();
                if (count >= SEUIL_MEDIUM) {
                    String message = (count >= SEUIL_HIGH)
                            ? "Brute-force massif : " + count + " échecs en 5 minutes"
                            : "Brute-force suspect : " + count + " échecs en 5 minutes";
                    alerts.add(new DetectionAlert(ip, message, getName(), debut));
                    break;
                }
            }
        }
        return alerts;
    }
}