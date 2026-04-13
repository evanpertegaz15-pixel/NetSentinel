import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import src.LogEntry;
import src.Parsing;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;

public class ParsingTest {
    @Test
    public void testIndexByIp() {
        Parsing parser = new Parsing();
        LogEntry e1 = new LogEntry("10.0.0.1", "-", "-", "15/Mar/2025:10:00:00 +0100",
                "GET", "/index.html", "HTTP/1.1", 200, 100, "-", "curl");
        LogEntry e2 = new LogEntry("10.0.0.1", "-", "-", "15/Mar/2025:10:01:00 +0100",
                "POST", "/login", "HTTP/1.1", 401, 50, "-", "curl");
        parser.indexIp(e1);
        parser.indexIp(e2);
        assertTrue(parser.getLogsIp().containsKey("10.0.0.1"));
        assertEquals(2, parser.getLogsIp().get("10.0.0.1").size());
    }

    @Test
    public void testIndexByTime() {
        Parsing parser = new Parsing();
        LogEntry e1 = new LogEntry("10.0.0.1", "-", "-", "15/Mar/2025:10:00:00 +0100",
                "GET", "/index.html", "HTTP/1.1", 200, 100, "-", "curl");
        LogEntry e2 = new LogEntry("10.0.0.1", "-", "-", "15/Mar/2025:10:00:00 +0100",
                "POST", "/login", "HTTP/1.1", 401, 50, "-", "curl");
        parser.indexTime(e1);
        parser.indexTime(e2);
        LocalDateTime key = parser.getLogsTime().firstKey();
        assertEquals(2, parser.getLogsTime().get(key).size());
    }

    @Test
    void testParseFile(@TempDir Path tempDir) throws Exception {
        Path logFile = tempDir.resolve("access.log");
        Files.writeString(logFile,
                "127.0.0.1 - - [10/Apr/2026:10:32:00 +0200] \"GET /index.html HTTP/1.1\" 200 123 \"-\" \"Mozilla\"\n" +
                        "192.168.0.1 - - [10/Apr/2026:10:33:00 +0200] \"POST /login HTTP/1.1\" 403 0 \"-\" \"Mozilla\""
        );
        Parsing p = new Parsing();
        p.parseFile(logFile.toString());
        assertEquals(2, p.getLogsIp().size());
        assertEquals(2, p.getLogsTime().size());
    }
}
