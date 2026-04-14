package src.reports;

import src.detectors.CorrelationAlert;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class BlockingRules {

    public static List<String> generate(Map<String, CorrelationAlert.Severity> severities) {
        List<String> rules =  new ArrayList<>();
        for (var entry : severities.entrySet()) {
            String ip = entry.getKey();
            CorrelationAlert.Severity severity = entry.getValue();
            if (severity == CorrelationAlert.Severity.HIGH || severity == CorrelationAlert.Severity.CRITICAL) {
                rules.add("BLOCK " + ip + " # Sévérité " + severity);
            }
        }
        return rules;
    }
}
