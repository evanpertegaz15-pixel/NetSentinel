package src.reports;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Whitelist {
    private static final Set<String> IP_WHITELIST = new HashSet<>();

    public static void load(String filepath) throws IOException {
        List<String> lines = Files.readAllLines(Path.of(filepath));
        for (String line : lines) {
            String ip = line.trim();
            if (!ip.isEmpty()) {
                IP_WHITELIST.add(ip);
            }
        }
    }

    public static boolean isWhitelisted(String ip) {
        return IP_WHITELIST.contains(ip);
    }
}
