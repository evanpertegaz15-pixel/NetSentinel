import model.LogEntry;
import parser.LogParser;
import src.StatsService;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

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
        List<LogEntry> logs = parseLogFile("accesslogclean.txt");
        StatsService.displayDashboard(logs);
    }
}