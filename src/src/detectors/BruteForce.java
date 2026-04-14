package src.src.detectors;

import src.src.LogEntry;
import src.src.model.Alert;
import src.src.model.Alert.Severity;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.Comparator;
import java.util.stream.Collectors;

public class BruteForce implements ThreatDetector {
    private static final int SEUIL_MEDIUM = 10;
    private static final int SEUIL_HIGH = 50;
    private static final Duration FENETRE = Duration.ofMinutes(5);

    @Override
    public List<Alert> analyze(List<LogEntry> logs) {
        Map<String, List<LocalDateTime>> echecsParIp = new HashMap<>();

        // Collecte des timestamps d'échecs (401/403) par IP
        for (LogEntry log : logs) {
            int status = log.getStatus();
            if (status == 401 || status == 403) {
                String ip = log.getIp();
                echecsParIp.computeIfAbsent(ip, k -> new ArrayList<>())
                        .add(log.getTimestamp());
            }
        }

        List<Alert> alerts = new ArrayList<>();

        // Analyse fenêtre glissante par IP
        for (Map.Entry<String, List<LocalDateTime>> entry : echecsParIp.entrySet()) {
            String ip = entry.getKey();
            List<LocalDateTime> echecs = entry.getValue();

            // Trie les timestamps
            Collections.sort(echecs);

            // Compte dans fenêtre de 5 min (début -> fin)
            for (int i = 0; i < echecs.size(); i++) {
                LocalDateTime debut = echecs.get(i);
                LocalDateTime fin = debut.plus(FENETRE);

                long count = echecs.stream()
                        .filter(t -> !t.isAfter(fin))  // t <= fin
                        .count();

                if (count >= SEUIL_MEDIUM) {
                    Severity severity = (count >= SEUIL_HIGH) ?
                            Severity.HIGH : Severity.MEDIUM;

                    alerts.add(new Alert(ip, debut, "BruteForce", severity, count));
                    break;  // Une alerte par IP suffit
                }
            }
        }

        return alerts.stream()
                .sorted(Comparator.comparing(Alert::getTimestamp).reversed())
                .collect(Collectors.toList());
    }
}