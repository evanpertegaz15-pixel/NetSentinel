package src.src.detectors;

import src.src.model.Alert;
import src.src.model.Alert.Severity;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class Ddos implements ThreatDetector {
    private static final double MULTIPLIER_IP = 10.0;
    private static final double MULTIPLIER_GLOBAL = 50.0;
    private static final Duration FENETRE_IP = Duration.ofSeconds(10);

    @Override
    public List<Alert> analyze(List<LogEntry> logs) {
        if (logs.isEmpty()) return new ArrayList<>();

        // Moyenne globale reqs/seconde
        LocalDateTime minTime = logs.stream().map(LogEntry::getTimestamp).min(LocalDateTime::compareTo).orElse(LocalDateTime.now());
        LocalDateTime maxTime = logs.stream().map(LogEntry::getTimestamp).max(LocalDateTime::compareTo).orElse(LocalDateTime.now());
        double dureeSecondes = Duration.between(minTime, maxTime).getSeconds();
        double moyenneGlobale = (double) logs.size() / Math.max(dureeSecondes, 1);

        Map<String, List<LogEntry>> logsParIp = logs.stream()
                .collect(Collectors.groupingBy(LogEntry::getIp));

        List<Alert> alerts = new ArrayList<>();

        // Par IP : fenêtre 10s
        for (Map.Entry<String, List<LogEntry>> entry : logsParIp.entrySet()) {
            String ip = entry.getKey();
            List<LogEntry> ipLogs = entry.getValue();
            Collections.sort(ipLogs, Comparator.comparing(LogEntry::getTimestamp));

            for (int i = 0; i < ipLogs.size(); i++) {
                LocalDateTime debut = ipLogs.get(i).getTimestamp();
                LocalDateTime fin = debut.plus(FENETRE_IP);

                long count = ipLogs.stream()
                        .filter(log -> !log.getTimestamp().isAfter(fin))
                        .count();

                if (count > moyenneGlobale * MULTIPLIER_IP) {
                    alerts.add(new Alert(ip, debut, "DDoS", Severity.HIGH, count));
                    break;
                }
            }
        }

        // Global : >50x moyenne
        if (logs.size() > moyenneGlobale * MULTIPLIER_GLOBAL * dureeSecondes) {
            alerts.add(new Alert("GLOBAL", minTime, "DDoS", Severity.CRITICAL, logs.size()));
        }

        return alerts.stream()
                .sorted(Comparator.comparing(Alert::getTimestamp).reversed())
                .collect(Collectors.toList());
    }
}