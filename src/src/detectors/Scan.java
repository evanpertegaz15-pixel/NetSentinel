package src.src.detectors;

import src.src.model.Alert;
import src.src.model.Alert.Severity;
import src.src.services.LogEntry;  // ← AJOUTÉ
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.Comparator;

public class Scan implements ThreatDetector {
    private static final Set<String> CHEMINS_SUSPECTS = Set.of(
            "/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/config.yml",
            "/.git/config", "/backup.sql", "/wp-admin", "/administrator", "/test"
    );
    private static final Set<String> USER_AGENTS_SUSPECTS = Set.of(
            "sqlmap", "nikto", "nmap", "dirbuster", "gobuster", "wfuzz"
    );
    private static final int SEUIL_404 = 20;

    @Override
    public List<Alert> analyze(List<LogEntry> logs) {
        Map<String, Set<String>> urls404ParIp = new HashMap<>();
        Map<String, Integer> count404ParIp = new HashMap<>();
        List<Alert> alerts = new ArrayList<>();  // ← DÉCLARÉ ICI

        for (LogEntry log : logs) {
            String ip = log.getIp();
            String request = log.getRequest();
            String userAgent = log.getUserAgent();
            int status = log.getStatus();

            // Compte 404 par IP
            if (status == 404) {
                count404ParIp.merge(ip, 1, Integer::sum);

                // URLs uniques 404
                if (request != null) {
                    urls404ParIp.computeIfAbsent(ip, k -> new HashSet<>()).add(request);
                }
            }

            // User-agent suspect OU chemin suspect → ALERTE IMMÉDIATE
            if ((request != null && CHEMINS_SUSPECTS.stream().anyMatch(request::contains)) ||
                    (userAgent != null && USER_AGENTS_SUSPECTS.stream().anyMatch(userAgent.toLowerCase()::contains))) {

                alerts.add(new Alert(ip, log.getTimestamp(), "Scan", Severity.MEDIUM, 1));
            }
        }

        // >20 URLs 404 différentes = scan répertoires (HIGH)
        for (Map.Entry<String, Set<String>> entry : urls404ParIp.entrySet()) {
            String ip = entry.getKey();
            if (entry.getValue().size() > SEUIL_404) {
                LocalDateTime ts = logs.stream()
                        .filter(l -> l.getIp().equals(ip) && l.getStatus() == 404)
                        .findFirst().map(LogEntry::getTimestamp).orElse(LocalDateTime.now());

                alerts.add(new Alert(ip, ts, "Scan", Severity.HIGH, entry.getValue().size()));
            }
        }

        return alerts.stream()
                .sorted(Comparator.comparing(Alert::getTimestamp).reversed())
                .collect(Collectors.toList());
    }
}