package src.detectors;

import src.LogEntry;
import java.util.*;

public class Scan extends Detector {
    private static final Set<String> SUSPICIOUS_PATHS = Set.of(
            "/admin",
            "/wp-login.php",
            "/.env",
            "/phpmyadmin",
            "/config.yml",
            "/.git/config",
            "/backup.sql"
    );
    private static final String[] SCAN_AGENTS = {"sqlmap", "nikto", "nmap", "dirbuster", "gobuster"};

    public Scan() {
        super("Scan");
    }

    @Override
    public List<DetectionAlert> detect(List<LogEntry> entries) {
        List<DetectionAlert> alerts = new ArrayList<>();
        for (LogEntry entry : entries) {
            String path = entry.getPath().toLowerCase();
            if (SUSPICIOUS_PATHS.contains(path)) {
                alerts.add(new DetectionAlert(entry.getIp(), "Accès à un chemin sensible : " + path, getName()));
            }
        }
        Set<String> flaggedUserAgent = new HashSet<>();
        for (LogEntry entry : entries) {
            String agent = entry.getUser().toLowerCase();
            String ip = entry.getIp();
            if (flaggedUserAgent.contains(ip)) {
                continue;
            }
            for (String scanner : SCAN_AGENTS) {
                if (agent.contains(scanner)) {
                    alerts.add(new DetectionAlert(entry.getIp(), "User-agent d’outil de scan détecté : " + scanner,  getName()));
                    flaggedUserAgent.add(ip);
                    break;
                }
            }
        }
        Map<String, Set<String>> url404 = new HashMap<>();
        for (LogEntry entry : entries) {
            if (entry.getStatus() == 404) {
                url404.computeIfAbsent(entry.getIp(), k -> new HashSet<>()).add(entry.getPath());
            }
        }
        for (var entry : url404.entrySet()) {
            String ip = entry.getKey();
            int count = entry.getValue().size();
            if (count > 20) {
                alerts.add(new DetectionAlert(ip, "Scan de répertoires : " + count + " URLs différentes en 404",  getName()));
            }
        }
        return alerts;
    }
}