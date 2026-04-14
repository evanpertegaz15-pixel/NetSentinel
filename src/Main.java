package src;

import src.src.model.Alert;  // Si Alert est dans model
import src.src.services.LogEntry;
import src.src.services.LogParser;
import src.src.services.StatsService;
import src.src.detectors.BruteForce;
import src.src.detectors.Ddos;
import src.src.detectors.InjectionSQL;
import src.src.detectors.Scan;

import java.io.BufferedReader;
import java.io.FileReader;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class Main {
    public static List<LogEntry> parseLogFile(String filename) {
        List<LogEntry> entries = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineNum = 0;
            while ((line = br.readLine()) != null) {
                lineNum++;
                LogEntry entry = LogParser.parse(line);
                if (entry != null) {
                    entries.add(entry);
                }
            }
            System.out.printf("Fichier %s : %d lignes, %d parsées\n", filename, lineNum, entries.size());
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
        return entries;
    }

    public static void main(String[] args) {
        // 1. Parsing (ton code existant)
        List<LogEntry> logs = parseLogFile("src/access_log_clean.txt");
        if (logs.isEmpty()) return;

        // 2. Dashboard (ton code existant)
        StatsService.displayDashboard(logs);

        // 3. NOUVEAU : Tous les détecteurs
        List<ThreatDetector> detecteurs = List.of(
                new BruteForce(),
                new Ddos(),
                new InjectionSQL(),
                new Scan()
        );

        // 4. Analyse complète
        List<Alert> allAlerts = detecteurs.stream()
                .flatMap(d -> d.analyze(logs).stream())
                .sorted(Comparator.comparing(Alert::getTimestamp).reversed())
                .collect(Collectors.toList());

        // 5. Affichage alertes
        System.out.println("\n ALERTES DÉTECTÉES (" + allAlerts.size() + "):");
        if (allAlerts.isEmpty()) {
            System.out.println("  Aucune menace détectée !");
        } else {
            // Par sévérité
            Map<Alert.Severity, Long> parSeverite = allAlerts.stream()
                    .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));
            System.out.println("  Par sévérité: " + parSeverite + "\n");

            // Détail
            allAlerts.forEach(alert ->
                    System.out.printf("  %s | %-15s | %-12s | %s | count=%d%n",
                            alert.getSeverity(), alert.getIp(), alert.getThreatType(),
                            alert.getTimestamp(), alert.getCount())
            );
        }
    }
}