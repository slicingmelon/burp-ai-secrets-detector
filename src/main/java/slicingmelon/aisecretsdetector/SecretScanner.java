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
            String responseString = response.toString(); // Convert once upfront since we can't use fast check
            
            // Declare variables outside loops for efficiency
            String secretValue;
            int searchStart;
            int highlightsCreated;
            int exactPos;
            int fullStartPos;
            int fullEndPos;
            Secret secret;
            
            for (SecretPattern pattern : secretPatterns) {
                try {
                    if (pattern.getName().equals("Generic Secret") && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        continue;
                    }

                    // Use regex on full response string for position calculation
                    Matcher matcher = pattern.getPattern().matcher(responseString);
                    
                    while (matcher.find()) {
                        
                        // Extract group info
                        if (pattern.getName().equals("Generic Secret") && matcher.groupCount() >= 1) {
                            secretValue = matcher.group(1);
                            
                            // Skip non-random strings etc.
                            if (!RandomnessAlgorithm.isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                continue;
                            }
                            
                            // Skip if the Generic Secret matches reCAPTCHA Site Key pattern
                            if (isRecaptchaSecret(secretValue)) {
                                continue;
                            }
                        } else {
                            // Use capture group if available to avoid boundary characters
                            if (matcher.groupCount() >= 1) {
                                secretValue = matcher.group(1);
                            } else {
                                secretValue = matcher.group(0);
                            }
                        }
                        
                        // Skip duplicates
                        if (uniqueSecretValues.contains(secretValue)) {
                            continue;
                        }
                        uniqueSecretValues.add(secretValue);
                        
                        // Find all occurrences of this secret in the response (like Burp Montoya API example)
                        searchStart = 0;
                        highlightsCreated = 0;
                        
                        while (searchStart < responseString.length() && highlightsCreated < maxHighlights) {
                            exactPos = responseString.indexOf(secretValue, searchStart);
                            
                            if (exactPos == -1) {
                                break; // No more occurrences
                            }
                            
                            // *** STEP 1: SECRET POSITION CALCULATION ***
                            // Found an occurrence - calculate exact start/end positions in response
                            // These positions will later be used to create RED response markers/highlights in Burp
                            fullStartPos = exactPos;
                            fullEndPos = fullStartPos + secretValue.length();
                            secret = new Secret(pattern.getName(), secretValue, fullStartPos, fullEndPos);
                            foundSecrets.add(secret);
                            highlightsCreated++;
                            
                            // Move search start past this occurrence
                            searchStart = exactPos + secretValue.length();
                        }
                        
                        // Log if we hit the limit and there might be more occurrences
                        if (highlightsCreated >= maxHighlights && searchStart < responseString.length()) {
                            int remainingPos = responseString.indexOf(secretValue, searchStart);
                            if (remainingPos != -1) {
                                config.appendToLog(String.format("Limited highlights for secret '%s' to %d (more occurrences exist but not highlighted for performance)", 
                                    secretValue, maxHighlights));
                            }
                        }
                    }
                } catch (Exception e) {
                    config.appendToLog("Error with pattern " + pattern.getName() + ": " + e.getMessage());
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