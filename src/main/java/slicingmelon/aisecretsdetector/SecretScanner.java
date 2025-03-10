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
        List<SecretPattern> patterns = new ArrayList<>();
        
        // AWS Access Key - no capturing group needed, matches the entire key
        patterns.add(new SecretPattern(
                "AWS Access Key",
                Pattern.compile("(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
        ));
        
        // API Key - use capturing group to get just the key
        patterns.add(new SecretPattern(
                "API Key",
                Pattern.compile("(?i)(?:api[_-]?key|apikey|secret)['\"]?\\s*[:=]\\s*['\"]([A-Za-z0-9]{16,64})['\"]")
        ));
        
        // Simple API key pattern without context - add this to catch the key in your example
        patterns.add(new SecretPattern(
                "API Key (Simple)",
                Pattern.compile("\"([A-Za-z0-9]{24,40})\"")
        ));
        
        // GitHub token pattern
        patterns.add(new SecretPattern(
                "GitHub Token",
                Pattern.compile("(?:github|gh)[_\\-]?(?:pat|token)['\"]?\\s*[:=]\\s*['\"]?([a-zA-Z0-9_]{35,40})['\"]?")
        ));
        
        // GitHub Personal Access Token pattern - direct match
        patterns.add(new SecretPattern(
                "GitHub PAT",
                Pattern.compile("ghp_[A-Za-z0-9]{36}")
        ));
        
        // TODO: Port more patterns from RipSecrets
        
        return patterns;
    }
    
    public SecretScanResult scanResponse(HttpRequestResponse requestResponse) {
        List<Secret> foundSecrets = new ArrayList<>();
        
        try {
            // Get response body as string - we need to do string operations
            String responseBody = requestResponse.response().bodyToString();
            
            // Process each pattern against the entire response body
            for (SecretPattern pattern : secretPatterns) {
                try {
                    Matcher matcher = pattern.getPattern().matcher(responseBody);
                    
                    while (matcher.find()) {
                        // Get the secret value and its positions
                        String secretValue;
                        int startPos;
                        int endPos;
                        
                        if (matcher.groupCount() >= 1) {
                            // Pattern has a capturing group - use it
                            secretValue = matcher.group(1);
                            startPos = matcher.start(1);
                            endPos = matcher.end(1);
                        } else {
                            // No capturing group - use the whole match
                            secretValue = matcher.group(0);
                            startPos = matcher.start(0);
                            endPos = matcher.end(0);
                        }
                        
                        // Calculate positions with 10 character buffer
                        int start = Math.max(0, startPos - 10);
                        int end = Math.min(responseBody.length(), endPos + 10);
                        
                        Secret secret = new Secret(pattern.getName(), secretValue, start, end);
                        foundSecrets.add(secret);
                        
                        api.logging().logToOutput(String.format(
                            "Found %s: '%s' at position %d-%d (highlighted range: %d-%d)",
                            pattern.getName(), secretValue, startPos, endPos, start, end
                        ));
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error with pattern " + pattern.getName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
        }
        
        return new SecretScanResult(requestResponse, foundSecrets);
    }
}