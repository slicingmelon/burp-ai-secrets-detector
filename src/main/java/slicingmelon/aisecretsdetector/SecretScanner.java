package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
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
        private final HttpResponse response;
        private final List<Secret> detectedSecrets;
        
        public SecretScanResult(HttpResponse response, List<Secret> detectedSecrets) {
            this.response = response;
            this.detectedSecrets = detectedSecrets;
        }
        
        public HttpResponse getResponse() {
            return response;
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
        
        // AWS Access Key - format AKIA... followed by 16 characters
        patterns.add(new SecretPattern(
                "AWS Access Key",
                Pattern.compile("\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\\b")
        ));
        
        // GitHub PAT - format ghp_... followed by 36 characters
        patterns.add(new SecretPattern(
                "GitHub PAT",
                Pattern.compile("(?:gh[oprsu]|github_pat)_[\\dA-Za-z_]{36}")
        ));
        
        // GCP API Key - format AIzaSy... followed by 33 characters
        patterns.add(new SecretPattern(
                "GCP API Key",
                Pattern.compile("AIzaSy[\\dA-Za-z_-]{33}")
        ));
        
        return patterns;
    }
    
    public SecretScanResult scanResponse(HttpResponse response) {
        List<Secret> foundSecrets = new ArrayList<>();
        
        try {
            // Get response body as string
            String responseBody = response.bodyToString();
            
            // Get the body offset - this tells us where the body begins in the full response
            int bodyOffset = response.bodyOffset();
            
            // Process each pattern against the body
            for (SecretPattern pattern : secretPatterns) {
                try {
                    Matcher matcher = pattern.getPattern().matcher(responseBody);
                    
                    while (matcher.find()) {
                        // Get the secret value and its positions - use the whole match for all patterns
                        String secretValue = matcher.group(0);
                        int bodyStartPos = matcher.start(0);
                        int bodyEndPos = matcher.end(0);
                        
                        // Convert body positions to full response positions by adding bodyOffset
                        int fullStartPos = bodyOffset + bodyStartPos;
                        int fullEndPos = bodyOffset + bodyEndPos;
                        
                        // Calculate highlight positions with 20 character buffer for better visibility
                        int highlightStart = Math.max(bodyOffset, fullStartPos - 20);
                        int highlightEnd = Math.min(bodyOffset + responseBody.length(), fullEndPos + 20);
                        
                        Secret secret = new Secret(pattern.getName(), secretValue, highlightStart, highlightEnd);
                        foundSecrets.add(secret);
                        
                        api.logging().logToOutput(String.format(
                            "Found %s: '%s' at body position %d-%d (highlight: %d-%d)",
                            pattern.getName(), secretValue, bodyStartPos, bodyEndPos, highlightStart, highlightEnd
                        ));
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error with pattern " + pattern.getName() + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
        }
        
        return new SecretScanResult(response, foundSecrets);
    }
}