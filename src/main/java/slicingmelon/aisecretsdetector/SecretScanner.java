package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;

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
    
    // Secret detection related classes
    public static class Secret {
        private final String type;
        private final String value;
        private final int lineNumber;
        
        public Secret(String type, String value, int lineNumber) {
            this.type = type;
            this.value = value;
            this.lineNumber = lineNumber;
        }
        
        public String getType() {
            return type;
        }
        
        public String getValue() {
            return value;
        }
        
        public int getLineNumber() {
            return lineNumber;
        }
    }
    
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
    
    public static class SecretScanResult {
        private final HttpRequestResponse requestResponse;
        private final List<Secret> detectedSecrets;
        
        public SecretScanResult(HttpRequestResponse requestResponse, List<Secret> detectedSecrets) {
            this.requestResponse = requestResponse;
            this.detectedSecrets = detectedSecrets;
        }
        
        public HttpRequestResponse getRequestResponse() {
            return requestResponse;
        }
        
        public List<Secret> getDetectedSecrets() {
            return detectedSecrets;
        }
        
        public boolean hasSecrets() {
            return !detectedSecrets.isEmpty();
        }
        
        public int getSecretCount() {
            return detectedSecrets.size();
        }
    }
    
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
        
        // GitHub token pattern
        patterns.add(new SecretPattern(
                "GitHub Token",
                Pattern.compile("(?:github|gh)[_\\-]?(?:pat|token)['\"]?\\s*[:=]\\s*['\"]([a-zA-Z0-9_]{35,40})['\"]")
        ));
        
        // TODO: Port more patterns from RipSecrets
        
        return patterns;
    }
    
    public SecretScanResult scanFile(File file, HttpRequestResponse requestResponse) throws IOException {
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
        
        return new SecretScanResult(requestResponse, foundSecrets);
    }
}