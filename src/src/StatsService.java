package src.src;

import java.util.*;
import java.util.stream.Collectors;

public class StatsService {
    public static void displayDashboard(List<LogEntry> entries) {
        System.out.println("=== DASHBOARD NETSENTINEL ===");

        System.out.println("1. Nombre total de requêtes parsées : " + entries.size());

        System.out.println("\n2. Top 10 des IPs les plus actives :");
        entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getIp, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(e -> System.out.printf("   %-15s : %d\n", e.getKey(), e.getValue()));

        System.out.println("\n3. Distribution des codes HTTP :");
        Map<Integer, Long> statusCounts = entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getStatus, Collectors.counting()));
        statusCounts.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(e -> System.out.printf("   %d : %d (%.1f%%)\n",
                        e.getKey(), e.getValue(), 100.0*e.getValue()/entries.size()));

        System.out.println("\n4. Top 10 des URLs les plus accédées :");
        entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getPath, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(e -> System.out.printf("   %-30s : %d\n", e.getKey(), e.getValue()));

        System.out.println("\n5. Top 5 des user-agents :");
        entries.stream()
                .collect(Collectors.groupingBy(LogEntry::getUser, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .forEach(e -> System.out.printf("   %-20s : %d\n", e.getKey(), e.getValue()));
    }
}