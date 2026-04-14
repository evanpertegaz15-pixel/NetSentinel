import src.logs.LogEntry;
import src.logs.LogParser;
import src.logs.StatsService;
import src.detectors.*;
import src.reports.Report;
import src.reports.Whitelist;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Main {
    static String cleanLogs = "src/access_log_clean.txt";
    static String attackLogs = "src/access_log_attack.txt";
    static List<Detector> detectors = List.of(
            new BruteForce(),
            new InjectionSQL(),
            new DDoS(),
            new Scan()
    );

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
            System.out.printf("\nFichier %s : %d lignes, %d parsées\n", filename, lineNum, entries.size());
        } catch (Exception e) {
            System.err.println("Erreur : " + e.getMessage());
        }
        return entries;
    }

    public static void detectorsLaunch() {
        for (Detector detector : detectors) {
            List<DetectionAlert> alerts = detector.detect(parseLogFile(attackLogs));
            if (!alerts.isEmpty()) {
                System.out.println("--- " + detector.getName() + " ---");
                for (DetectionAlert alert : alerts) {
                    System.out.println(alert.getIp() + " -> " + alert.getMessage());
                }
            }
        }
    }

    public static void scoringDetectors() {
        List<DetectionAlert> allAlerts = new ArrayList<>();
        for (Detector detector : detectors) {
            allAlerts.addAll(detector.detect(parseLogFile(attackLogs)));
        }
        CorrelationAlert alert = new CorrelationAlert();
        Map<String, CorrelationAlert.Severity> scores = alert.correlate(allAlerts);
        System.out.println("--- SCORING DES ALERTES ---");
        for (var entry : scores.entrySet()) {
            System.out.println(entry.getKey() + " -> " + entry.getValue());
        }
    }

    public static void reportGeneration() {
        List<DetectionAlert> allAlerts = new ArrayList<>();
        for (Detector detector : detectors) {
            allAlerts.addAll(detector.detect(parseLogFile(attackLogs)));
        }
        CorrelationAlert alert = new CorrelationAlert();
        Map<String, CorrelationAlert.Severity> severites = alert.correlate(allAlerts);
        try {
            Report.generateReport(allAlerts, severites, "rapport_securite.txt");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static void main(String[] args) {
        List<LogEntry> logs = parseLogFile(cleanLogs);
        StatsService.displayDashboard(logs);
        try {
            Whitelist.load("whitelist.txt");
        }  catch (IOException e) {
            e.printStackTrace();
        }
        detectorsLaunch();
        scoringDetectors();
        reportGeneration();
    }
}