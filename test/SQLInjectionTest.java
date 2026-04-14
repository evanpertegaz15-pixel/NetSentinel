import org.junit.jupiter.api.Test;
import src.logs.LogEntry;
import src.detectors.DetectionAlert;
import src.detectors.InjectionSQL;
import java.time.LocalDateTime;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SQLInjectionTest {
    @Test
    void testSqlInjectionPatternTriggersAlert() {
        LocalDateTime date = LocalDateTime.of(2025, 3, 15, 10, 2, 55);
        LogEntry entry = new LogEntry("192.168.0.10", date, "GET", "/login?user=admin' OR 1=1", 200, "Mozilla");
        InjectionSQL detector = new InjectionSQL();
        List<DetectionAlert> alerts = detector.detect(List.of(entry));
        assertEquals(1, alerts.size(), "Une alerte SQL injection devrait être détectée");
        assertTrue(alerts.get(0).getMessage().toLowerCase().contains("sql"), "Le message doit mentionner une injection SQL");
        assertEquals("192.168.0.10", alerts.get(0).getIp(), "L'IP doit correspondre à celle du log");
    }
}