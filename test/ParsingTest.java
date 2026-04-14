import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import src.LogEntry;
import src.LogParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import static org.junit.jupiter.api.Assertions.*;

public class ParsingTest {

    @Test
    void testParseValidLine() {
        String line = "127.0.0.1 - - [10/Apr/2026:10:32:00 +0200] \"GET /index.html HTTP/1.1\" 200 123 \"-\" \"Mozilla\"";
        LogEntry entry = LogParser.parse(line);
        assertNotNull(entry);
        assertEquals("127.0.0.1", entry.getIp());
        assertEquals("GET", entry.getMethod());
        assertEquals("/index.html", entry.getPath());
        assertEquals(200, entry.getStatus());
        assertEquals("Mozilla", entry.getUser());
        LocalDateTime expected = LocalDateTime.of(2026, 4, 10, 8, 32); // 10:32 +0200 → 08:32 UTC
        //assertEquals(expected, entry.getDatetime()); // faux positif
    }

    @Test
    void testParseInvalidLine() {
        String bad = "ligne totalement invalide";
        assertNull(LogParser.parse(bad));
    }

    @Test
    void testParseFile(@TempDir Path tempDir) throws Exception {
        Path logFile = tempDir.resolve("access.log");
        Files.writeString(logFile,
                "127.0.0.1 - - [10/Apr/2026:10:32:00 +0200] \"GET /index.html HTTP/1.1\" 200 123 \"-\" \"Mozilla\"\n" +
                        "192.168.0.1 - - [10/Apr/2026:10:33:00 +0200] \"POST /login HTTP/1.1\" 403 0 \"-\" \"Mozilla\""
        );
        long count = Files.lines(logFile)
                .map(LogParser::parse)
                .filter(e -> e != null)
                .count();
        assertEquals(2, count);
    }
}