package src.src;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser {
    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(?<ip>\\S+)\\s+(?<ident>\\S+)\\s+(?<user>\\S+)\\s+\\[(?<datetime>[^]]+)]\\s+\"(?<method>\\S+)\\s+(?<path>\\S+)\\s+(?<protocol>[^\"]+)\"\\s+(?<status>\\d+)\\s+(?<size>\\d+)\\s+\"(?<referrer>[^\"]*)\"\\s+\"(?<agent>[^\"]*)\"$"
    );

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    public static LogEntry parse(String line) {
        Matcher matcher = LOG_PATTERN.matcher(line.trim());
        if (!matcher.matches()) {
            return null;
        }
        try {
            String ip = matcher.group("ip");
            String datetime = matcher.group("datetime");
            String method = matcher.group("method");
            String path = matcher.group("path");
            int status = Integer.parseInt(matcher.group("status"));
            String agent = matcher.group("agent");
            LocalDateTime timestamp = ZonedDateTime
                    .parse(datetime, DATE_TIME_FORMATTER)
                    .withZoneSameInstant(ZoneOffset.UTC)
                    .toLocalDateTime();

            return new LogEntry(ip, timestamp, method, path, status, agent);
        } catch (Exception e) {
            return null;
        }
    }
}