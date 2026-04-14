import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import src.LogEntry;
import src.detectors.DetectionAlert;
import src.detectors.InjectionSQL;
import src.reports.Whitelist;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class WhitelistTest {
    @BeforeEach
    void setup() throws IOException {
        Files.writeString(Path.of("whitelist.txt"), "192.168.0.50\n");
        Whitelist.load("whitelist.txt");
    }

    @Test
    void testWhitelistedIpGeneratesNoAlert() {
        InjectionSQL detector = new InjectionSQL();
        LogEntry entry = new LogEntry("192.168.0.50", LocalDateTime.now(), "GET", "/login?user=admin' OR 1=1", 200, "Mozilla");
        List<DetectionAlert> alerts = detector.detect(List.of(entry));
        assertEquals(0, alerts.size(), "Une IP whitelist ne doit générer aucune alerte");
    }
}
