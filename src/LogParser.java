package src;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import LogEntry;

public class LogParser {
    // Regex TESTÉE sur les 3 exemples du sujet
    private static final Pattern PATTERN = Pattern.compile(
            "^(\\S+)\\s+(-?\\S*)\\s+(-?\\S*)\\s+(\\d{2})(\\w{3})(\\d{4})(\\d{2})(\\d{2})(\\d{2})\\s+(\\d{4})\\s+(\\w+)\\s+(.+?)\\s+HTTP[^\\s]+\\s+(\\d{3})\\s+\\d+\\s+-\\s+(\\S+)$"
    );

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss z", java.util.Locale.ENGLISH);

    public static LogEntry parse(String line) {
        Matcher matcher = PATTERN.matcher(line.trim());
        if (!matcher.matches()) {
            return null;
        }

        try {
            String ip = matcher.group(1);
            String ident = matcher.group(2);
            String user = matcher.group(3);
            String day = matcher.group(4);
            String month = matcher.group(5);
            String year = matcher.group(6);
            String hour = matcher.group(7);
            String minute = matcher.group(8);
            String second = matcher.group(9);
            String tz = matcher.group(10);

            // Reconstruit timestamp
            String dateStr = String.format("%s/%s/%s:%s:%s:%s %s",
                    day, month, year, hour, minute, second, tz);

            LocalDateTime timestamp = LocalDateTime.parse(dateStr, FORMATTER);
            String method = matcher.group(11);
            String url = matcher.group(12);
            int statusCode = Integer.parseInt(matcher.group(13));
            String userAgent = matcher.group(14);

            return new LogEntry(ip, timestamp, method, url, statusCode, userAgent);
        } catch (Exception e) {
            return null;
        }
    }
}