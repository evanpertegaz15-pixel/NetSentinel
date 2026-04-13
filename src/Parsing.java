import java.io.File;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Parsing {
    private static final Pattern LOG_PATTERN = Pattern.compile("^(?<ip>\\S+)\\s+(?<ident>\\S+)\\s+(?<user>\\S+)\\s+\\[(?<datetime>[^]]+)]\\s+\"(?<method>\\S+)\\s+(?<path>\\S+)\\s+(?<protocol>[^\"]+)\"\\s+(?<status>\\d+)\\s+(?<size>\\d+)\\s+\"(?<referrer>[^\"]*)\"\\s+\"(?<agent>[^\"]*)\"$");
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
    private final Map<String, List<LogEntry>> logsIp = new HashMap<>();
    private final TreeMap<LocalDateTime, List<LogEntry>> logsTime = new TreeMap<>();

    public Map<String, List<LogEntry>> getLogsIp() {
        return this.logsIp;
    }

    public TreeMap<LocalDateTime, List<LogEntry>> getLogsTime() {
        return this.logsTime;
    }

    public void parseFile(String file) {
        try (Scanner sc = new Scanner(new File(file))) {
            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                LogEntry entry = parseLine(line);
                if (entry != null) {
                    indexIp(entry);
                    indexTime(entry);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected LogEntry parseLine(String line) {
        Matcher matcher = LOG_PATTERN.matcher(line);
        if (!matcher.matches()) {
            return null;
        }
        return new LogEntry(
                matcher.group("ip"),
                matcher.group("ident"),
                matcher.group("user"),
                matcher.group("datetime"),
                matcher.group("method"),
                matcher.group("path"),
                matcher.group("protocol"),
                Integer.parseInt(matcher.group("status")),
                Integer.parseInt(matcher.group("size")),
                matcher.group("referrer"),
                matcher.group("agent")
        );
    }

    protected void indexIp(LogEntry entry) {
        logsIp.computeIfAbsent(entry.ip, k -> new ArrayList<>()).add(entry);
    }

    protected void indexTime(LogEntry entry) {
        LocalDateTime time = ZonedDateTime.parse(entry.datetime, DATE_TIME_FORMATTER).withZoneSameInstant(ZoneOffset.UTC).toLocalDateTime();
        logsTime.computeIfAbsent(time, k -> new ArrayList<>()).add(entry);
    }
}
