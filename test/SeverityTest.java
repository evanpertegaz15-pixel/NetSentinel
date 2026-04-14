import org.junit.jupiter.api.Test;
import src.detectors.CorrelationAlert;
import src.detectors.DetectionAlert;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class SeverityTest {
    @Test
    void testSeverityIncreasesWithDetectorCount() {
        CorrelationAlert alert = new CorrelationAlert();
        LocalDateTime date = LocalDateTime.now();
        //MEDIUM
        List<DetectionAlert> alerts1 = List.of(
                new DetectionAlert("10.0.0.1", "SQL injection", "SQL Injection", date)
        );
        Map<String, CorrelationAlert.Severity> result1 = alert.correlate(alerts1);
        assertEquals(CorrelationAlert.Severity.MEDIUM, result1.get("10.0.0.1"));
        //HIGH
        List<DetectionAlert> alerts2 = List.of(
                new DetectionAlert("10.0.0.2", "SQL injection", "SQL Injection",  date),
                new DetectionAlert("10.0.0.2", "Brute force", "Brute Force",  date)
        );
        Map<String, CorrelationAlert.Severity> result2 = alert.correlate(alerts2);
        assertEquals(CorrelationAlert.Severity.HIGH, result2.get("10.0.0.2"));
        //CRITICAL
        List<DetectionAlert> alerts3 = List.of(
                new DetectionAlert("10.0.0.3", "SQL injection", "SQL Injection",  date),
                new DetectionAlert("10.0.0.3", "Brute force", "Brute Force", date),
                new DetectionAlert("10.0.0.3", "Scan", "Scan",  date)
        );
        Map<String, CorrelationAlert.Severity> result3 = alert.correlate(alerts3);
        assertEquals(CorrelationAlert.Severity.CRITICAL, result3.get("10.0.0.3"));
    }
}
