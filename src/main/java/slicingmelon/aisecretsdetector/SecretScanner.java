package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpResponseReceived;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretScanner {
    
    private final MontoyaApi api;
    private final List<SecretPattern> secretPatterns;
    
    public SecretScanner(MontoyaApi api) {
        this.api = api;
        this.secretPatterns = initializeSecretPatterns();
    }
    
    private List<SecretPattern> initializeSecretPatterns() {
        // This is where we'll initialize the secret patterns from RipSecrets
        // For now, adding a few basic patterns as placeholders
        List<SecretPattern> patterns = new ArrayList<>();
        
        // AWS key pattern
        patterns.add(new SecretPattern(
                "AWS Access Key",
                Pattern.compile("(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
        ));
        
        // Generic API key pattern
        patterns.add(new SecretPattern(
                "API Key",
                Pattern.compile("(?i)(?:api[_-]?key|apikey|secret)['\"]?\\s*[:=]\\s*['\"]([A-Za-z0-9]{16,64})['\"]")
        ));
        
        // TODO: Add more patterns from RipSecrets
        
        return patterns;
    }
    
    public ScanResult scanFile(File file, HttpResponseReceived responseReceived) throws IOException {
        List<Secret> foundSecrets = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                
                for (SecretPattern pattern : secretPatterns) {
                    Matcher matcher = pattern.getPattern().matcher(line);
                    
                    while (matcher.find()) {
                        String secretValue = matcher.groupCount() >= 1 ? matcher.group(1) : matcher.group(0);
                        Secret secret = new Secret(pattern.getName(), secretValue, lineNumber);
                        foundSecrets.add(secret);
                    }
                }
            }
        }
        
        return new ScanResult(responseReceived, foundSecrets);
    }
    
    // Inner classes to represent secret patterns, results, etc.
    public static class SecretPattern {
        private final String name;
        private final Pattern pattern;
        
        public SecretPattern(String name, Pattern pattern) {
            this.name = name;
            this.pattern = pattern;
        }
        
        public String getName() {
            return name;
        }
        
        public Pattern getPattern() {
            return pattern;
        }
    }
}