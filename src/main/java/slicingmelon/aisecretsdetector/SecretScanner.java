/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

public class SecretScanner {
    private final UIConfig config;
    private final List<SecretPattern> secretPatterns;
    
    private static Pattern cachedRecaptchaPattern = null;

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
        //this.api = api;
        this.secretPatterns = SecretScannerUtils.getAllPatterns();
        this.config = UIConfig.getInstance();
    }
    
    public SecretScanResult scanResponse(HttpResponse response) {
        List<Secret> foundSecrets = new ArrayList<>();
        Set<String> uniqueSecretValues = new HashSet<>();
        
        // Get max highlights setting once outside all loops for efficiency
        int maxHighlights = config.getConfigSettings().getMaxHighlightsPerSecret();
        
        try {
            // Use ByteArray directly instead of converting entire response to string
            ByteArray responseBytes = response.toByteArray();
            
            // Declare variables outside loops for efficiency
            String secretValue;
            int highlightsCreated;
            int matchPos;
            int contextStart;
            int contextEnd;
            String contextString;
            Matcher contextMatcher;
            Secret secret;
            
            for (SecretPattern pattern : secretPatterns) {
                try {
                    if (pattern.getName().equals("Generic Secret") && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        continue;
                    }

                    // Use ByteArray indexOf to find matches efficiently
                    matchPos = 0;
                    highlightsCreated = 0;
                    
                    while (matchPos < responseBytes.length() && highlightsCreated < maxHighlights) {
                        // Find next match position using ByteArray API
                        matchPos = responseBytes.indexOf(pattern.getPattern(), matchPos, responseBytes.length());
                        
                        if (matchPos == -1) {
                            break; // No more matches
                        }
                        
                        // Extract context around the match for group processing
                        // We need enough context to ensure we capture the full match with groups
                        contextStart = matchPos;
                        contextEnd = Math.min(responseBytes.length(), matchPos + 200);
                        
                        // Convert only this small context to string
                        ByteArray contextBytes = responseBytes.subArray(contextStart, contextEnd);
                        contextString = contextBytes.toString();
                        
                        // Apply the full regex with groups on this context
                        contextMatcher = pattern.getPattern().matcher(contextString);
                        
                        // Find the match within this context
                        if (contextMatcher.find()) {
                            // Extract group info
                            if (pattern.getName().equals("Generic Secret") && contextMatcher.groupCount() >= 1) {
                                secretValue = contextMatcher.group(1);
                                
                                // Skip non-random strings etc.
                                if (!RandomnessAlgorithm.isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                    matchPos++;
                                    continue;
                                }
                                
                                // Skip if the Generic Secret matches reCAPTCHA Site Key pattern
                                if (isRecaptchaSecret(secretValue)) {
                                    matchPos++;
                                    continue;
                                }
                            } else {
                                // Use capture group if available to avoid boundary characters
                                if (contextMatcher.groupCount() >= 1) {
                                    secretValue = contextMatcher.group(1);
                                } else {
                                    secretValue = contextMatcher.group(0);
                                }
                            }
                            
                            // Skip duplicates
                            if (uniqueSecretValues.contains(secretValue)) {
                                matchPos++;
                                continue;
                            }
                            uniqueSecretValues.add(secretValue);
                            
                            // Find exact position of the secret value in the full response
                            int secretStartInResponse = responseBytes.indexOf(secretValue, false, contextStart, responseBytes.length());
                            if (secretStartInResponse != -1) {
                                int secretEndInResponse = secretStartInResponse + secretValue.length();
                                
                                secret = new Secret(pattern.getName(), secretValue, secretStartInResponse, secretEndInResponse);
                                foundSecrets.add(secret);
                                highlightsCreated++;
                                
                                // Move search past this match
                                matchPos = secretStartInResponse + secretValue.length();
                            } else {
                                // Fallback: couldn't find exact position, move past context match
                                matchPos = contextStart + contextMatcher.end();
                            }
                        } else {
                            // This shouldn't happen, but if it does, move forward
                            matchPos++;
                        }
                    }
                    
                    // Log if we hit the limit
                    if (highlightsCreated >= maxHighlights) {
                        int remainingMatches = responseBytes.countMatches(pattern.getPattern(), matchPos, responseBytes.length());
                        if (remainingMatches > 0) {
                            config.appendToLog(String.format("Limited highlights for pattern '%s' to %d (approximately %d more matches exist but not highlighted for performance)", 
                                pattern.getName(), maxHighlights, remainingMatches));
                        }
                    }
                } catch (Exception e) {
                    String errorMsg = e.getMessage();
                    if (errorMsg == null) {
                        errorMsg = e.getClass().getSimpleName();
                    }
                    config.appendToLog("Error with pattern " + pattern.getName() + ": " + errorMsg);
                }
            }
        } catch (Exception e) {
            config.appendToLog("Error scanning response: " + e.getMessage());
        }
        
        return new SecretScanResult(response, foundSecrets);
    }
    
    /**
     * Helper method to check if a secret matches the Google reCAPTCHA pattern
     */
    private boolean isRecaptchaSecret(String secretValue) {
        if (cachedRecaptchaPattern == null) {
            // Find and cache the pattern once
            for (SecretPattern sp : secretPatterns) {
                if (sp.getName().equals("Google reCAPTCHA Key")) {
                    cachedRecaptchaPattern = sp.getPattern();
                    break;
                }
            }
        }
        return cachedRecaptchaPattern != null && cachedRecaptchaPattern.matcher(secretValue).matches();
    }
}