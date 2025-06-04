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

    // Secret detection related classes
    public static class Secret {
        private final String type;
        private final String value;
        private final int startIndex;
        private final int endIndex;
        private final int responsePosition;
        
        public Secret(String type, String value, int startIndex, int endIndex, int responsePosition) {
            this.type = type;
            this.value = value;
            this.startIndex = startIndex;
            this.endIndex = endIndex;
            this.responsePosition = responsePosition;
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
        
        public int getResponsePosition() {
            return responsePosition;
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
        
        // Find reCAPTCHA Site Key pattern for filtering Generic Secrets
        Pattern googleRecaptchaSiteKeyPattern = null;
        for (SecretPattern sp : secretPatterns) {
            if (sp.getName().equals("Google reCAPTCHA Key")) {
                googleRecaptchaSiteKeyPattern = sp.getPattern();
                break;
            }
        }
        
        try {
            String responseString = response.toString(); // Convert once upfront since we can't use fast check
            
            for (SecretPattern pattern : secretPatterns) {
                try {
                    if (pattern.getName().equals("Generic Secret") && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        continue;
                    }

                    // Use regex on full response string for position calculation
                    Matcher matcher = pattern.getPattern().matcher(responseString);
                    
                    while (matcher.find()) {
                        String secretValue;
                        int responseStartPos;
                        
                        // Extract group info
                        if (pattern.getName().equals("Generic Secret") && matcher.groupCount() >= 1) {
                            secretValue = matcher.group(1);
                            responseStartPos = matcher.start(1);
                            
                            // Skip non-random strings etc.
                            if (!RandomnessAlgorithm.isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                continue;
                            }
                            
                            // Skip if the Generic Secret matches reCAPTCHA Site Key pattern
                            if (googleRecaptchaSiteKeyPattern != null && googleRecaptchaSiteKeyPattern.matcher(secretValue).matches()) {
                                continue;
                            }
                        } else {
                            // Use capture group if available to avoid boundary characters
                            if (matcher.groupCount() >= 1) {
                                secretValue = matcher.group(1);
                                responseStartPos = matcher.start(1);
                            } else {
                                secretValue = matcher.group(0);
                                responseStartPos = matcher.start(0);
                            }
                        }
                        
                        // Skip duplicates
                        if (uniqueSecretValues.contains(secretValue)) {
                            continue;
                        }
                        uniqueSecretValues.add(secretValue);
                        
                        // Find all occurrences of this secret in the response (like Burp Montoya API example)
                        int searchStart = 0;
                        boolean foundAtLeastOne = false;
                        
                        while (searchStart < responseString.length()) {
                            int exactPos = responseString.indexOf(secretValue, searchStart);
                            
                            if (exactPos == -1) {
                                break; // No more occurrences
                            }
                            
                            // Found an occurrence - create a secret for this position
                            int fullStartPos = exactPos;
                            int fullEndPos = fullStartPos + secretValue.length();
                            Secret secret = new Secret(pattern.getName(), secretValue, fullStartPos, fullEndPos, exactPos);
                            foundSecrets.add(secret);
                            foundAtLeastOne = true;
                            
                            // Move search start past this occurrence
                            searchStart = exactPos + secretValue.length();
                        }
                        
                        // Fallback to regex position if indexOf completely fails
                        if (!foundAtLeastOne) {
                            config.appendToLog("Warning: Could not find secret using indexOf, using regex position for: " + secretValue);
                            int fullStartPos = responseStartPos;
                            int fullEndPos = fullStartPos + secretValue.length();
                            Secret secret = new Secret(pattern.getName(), secretValue, fullStartPos, fullEndPos, responseStartPos);
                            foundSecrets.add(secret);
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
}