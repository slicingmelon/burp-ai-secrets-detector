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
        private final int startIndex;
        private final int endIndex;
        
        public Secret(String type, String value, int startIndex, int endIndex) {
            this.type = type;
            this.value = value;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
        }
        
        public String getType() {
            return type;
        }
        
        public String getValue() {
            return value;
        }
        
        public int getStartIndex() {
            return startIndex;
        }
        
        public int getEndIndex() {
            return endIndex;
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
    
    public SecretScanResult scanResponse(HttpRequestResponse requestResponse) {
        List<Secret> foundSecrets = new ArrayList<>();
        
        // Read the response body
        String responseBody = requestResponse.response().bodyToString();
        
        // Process each pattern against the entire response body
        for (SecretPattern pattern : secretPatterns) {
            Matcher matcher = pattern.getPattern().matcher(responseBody);
            
            while (matcher.find()) {
                String secretValue;
                int startPosition;
                int endPosition;
                
                // Handle patterns with or without capturing groups
                if (matcher.groupCount() >= 1) {
                    // Use capturing group if available
                    secretValue = matcher.group(1);
                    startPosition = matcher.start(1);
                    endPosition = matcher.end(1);
                } else {
                    // Use whole match if no capturing group
                    secretValue = matcher.group(0);
                    startPosition = matcher.start(0);
                    endPosition = matcher.end(0);
                }
    
                // Calculate positions with 10 character buffer
                int start = Math.max(0, startPosition - 10);
                int end = Math.min(responseBody.length(), endPosition + 10);
                
                Secret secret = new Secret(pattern.getName(), secretValue, start, end);
                foundSecrets.add(secret);
                
                api.logging().logToOutput(String.format(
                    "Found %s: %s at position %d-%d (highlighted range: %d-%d)",
                    pattern.getName(), secretValue, startPosition, endPosition, start, end
                ));
            }
        }
        
        return new SecretScanResult(requestResponse, foundSecrets);
    }
}