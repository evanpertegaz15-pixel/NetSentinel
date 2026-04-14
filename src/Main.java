import src.LogEntry;
import src.LogParser;
import src.StatsService;
import src.detectors.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class Main {
    static String cleanLogs = "src/access_log_clean.txt";
    static String attackLogs = "src/access_log_attack.txt";

    static List<Detector> detectors = List.of(
            //new BruteForce(),
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

    public static void detectSQL() {
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

    static void main(String[] args) {
        List<LogEntry> logs = parseLogFile(cleanLogs);
        StatsService.displayDashboard(logs);
        detectSQL();
    }
}