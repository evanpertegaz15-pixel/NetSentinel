package src.reports;

import src.detectors.CorrelationAlert;
import src.detectors.DetectionAlert;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Report {

    public static void generateReport(List<DetectionAlert> alerts, Map<String, CorrelationAlert.Severity> severities, String filepath) throws IOException {
        try (FileWriter writer = new FileWriter(filepath)) {
            writer.write("--- RAPPORT DE SECURITE ---\n\n");
            writer.write("Résumé exécutif\n");
            writer.write("---------------\n");
            Map<CorrelationAlert.Severity, Long> countBySeverity = severities.values().stream().collect(Collectors.groupingBy(s -> s, Collectors.counting()));
            for (var entry : countBySeverity.entrySet()) {
                writer.write(String.format(" - %s : %d IP(s)\n", entry.getKey(), entry.getValue()));
            }
            List<String> criticalIps = severities.entrySet().stream().filter(e -> e.getValue() == CorrelationAlert.Severity.CRITICAL).map(Map.Entry::getKey).toList();
            writer.write("\nIPs les plus dangereuses :\n");
            if (criticalIps.isEmpty()) {
                writer.write(" - Aucune IP critique détectée\n");
            } else {
                for (String ip : criticalIps) {
                    writer.write(" - " + ip + "\n");
                }
            }
            writer.write("\n\n");
            writer.write("Timeline des incidents\n");
            writer.write("----------------------\n");
            List<DetectionAlert> sortedAlerts = alerts.stream().sorted(Comparator.comparing(DetectionAlert::getDate)).toList();
            for (DetectionAlert alert : sortedAlerts) {
                writer.write(String.format("[%s] %s -> %s (%s)\n", alert.getDate(), alert.getIp(), alert.getMessage(), alert.getDetector()));
            }
            writer.write("\n\n");
            writer.write("Détail par IP suspecte\n");
            writer.write("----------------------\n");
            Map<String, List<DetectionAlert>> ipAlerts = alerts.stream().collect(Collectors.groupingBy(DetectionAlert::getIp));
            for (String ip : ipAlerts.keySet()) {
                writer.write("\nIP : " + ip + "\n");
                writer.write("Sévérité finale : " + severities.get(ip) + "\n");
                for (DetectionAlert alert : ipAlerts.get(ip)) {
                    writer.write(" - " + alert.getMessage() + " (" + alert.getDetector() + ")\n");
                }
            }
            writer.write("\n\n");
            writer.write("Recommandations\n");
            writer.write("---------------\n");
            writer.write("""
                    - Brute Force :
                        * Activer le rate limiting
                        * Imposer un délai entre les tentatives
                        * Activer l'authentification multi-facteurs
                    
                    - Injection SQL :
                        * Utiliser des requêtes préparées
                        * Activer un pare-feu
                        * Valider et échapper toutes les entrées utilisateur
                    
                    - Scan de vulnérabilités :
                        * Bloquer automatiquement les IP scanneuses
                        * Surveiller les accès aux endpoints sensibles
                        * Activer la détection d'anomalies réseau
                    
                    - DDoS :
                        * Mettre en place un système anti-DDoS
                        * Limiter le nombre de connexions simultanées par IP
                        * Surveiller les pics de trafic anormaux
                    """);
            writer.write("\n\n");
            writer.write("Règles de blocage\n");
            writer.write("-----------------\n");
            List<String> rules = BlockingRules.generate(severities);
            if (rules.isEmpty()) {
                writer.write("Aucune IP à bloquer.\n");
            } else {
                for (String rule : rules) {
                    writer.write(" - " + rule + "\n");
                }
            }
        }
    }
}
