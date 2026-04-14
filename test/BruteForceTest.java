import org.junit.jupiter.api.Test;
import src.logs.LogEntry;
import src.detectors.BruteForce;
import src.detectors.DetectionAlert;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BruteForceTest {
    @Test
    void testBruteForceTriggeredBy15FailuresIn2Minutes() {
        BruteForce detector = new BruteForce();
        List<LogEntry> logs = new ArrayList<>();
        LocalDateTime start = LocalDateTime.of(2025, 3, 15, 10, 0);
        for (int i = 0; i < 15; i++) {
            logs.add(new LogEntry("192.168.0.50", start.plusSeconds(i * 8), "GET", "/login", 401, "Mozilla"));
        }
        List<DetectionAlert> alerts = detector.detect(logs);
        assertEquals(1, alerts.size(), "Une alerte brute-force devrait être déclenchée");
        assertEquals("192.168.0.50", alerts.get(0).getIp());
        assertTrue(alerts.get(0).getMessage().contains("Brute-force"));
    }
}