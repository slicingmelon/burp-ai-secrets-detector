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
    
    // Helper class for returning both start and end positions
    public static class MatchResult {
        public final int startPos;
        public final int endPos;
        
        public MatchResult(int startPos, int endPos) {
            this.startPos = startPos;
            this.endPos = endPos;
        }
    }
    
    /**
     * Find pattern match bounds in ByteArray and return both start and end positions
     * @param data ByteArray to search in
     * @param pattern Pattern to search for
     * @param startIndex Where to start searching
     * @return MatchResult with start and end positions, or null if no match found
     */
    private static MatchResult findPatternBounds(ByteArray data, Pattern pattern, int startIndex) {
        // First, find the match position using ByteArray's indexOf
        int matchStart = data.indexOf(pattern, startIndex, data.length());
        if (matchStart == -1) {
            return null;
        }
        
        // To find the end position, we need to apply the regex to a small portion
        // Extract a reasonable chunk around the match (but not too much to avoid overflow)
        int extractStart = Math.max(0, matchStart - 10); // Small buffer before
        int extractEnd = Math.min(data.length(), matchStart + 300); // Reasonable buffer after
        
        try {
            ByteArray matchRegion = data.subArray(extractStart, extractEnd);
            String matchRegionString = matchRegion.toString();
            
            Matcher matcher = pattern.matcher(matchRegionString);
            
            // Find the match in the extracted region
            int regionMatchPos = matchStart - extractStart;
            if (matcher.find(regionMatchPos)) {
                // Calculate actual positions in the original ByteArray
                int actualStart = extractStart + matcher.start();
                int actualEnd = extractStart + matcher.end();
                return new MatchResult(actualStart, actualEnd);
            }
        } catch (Exception e) {
            // Fallback: assume the match is at least 1 character
            return new MatchResult(matchStart, matchStart + 1);
        }
        
        return null;
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

        List<SecretPattern> patterns;
        UIConfig configInstance;
        
        try {
            //this.api = api;
            patterns = SecretScannerUtils.getAllPatterns();
            configInstance = UIConfig.getInstance();
            
            AISecretsDetector.getInstance().logMsg("SecretScanner initialized with " + patterns.size() + " patterns");
        } catch (Exception e) {
            AISecretsDetector.getInstance().logMsgError("Error initializing SecretScanner: " + e.getMessage());
            e.printStackTrace();
            patterns = new ArrayList<>(); // fallback to empty list
            configInstance = UIConfig.getInstance();
        }
        
        this.secretPatterns = patterns;
        this.config = configInstance;
    }
    
    public SecretScanResult scanResponse(HttpResponse response) {
        List<Secret> foundSecrets = new ArrayList<>();
        Set<String> uniqueSecretValues = new HashSet<>();
        
        // Get max highlights setting once outside all loops for efficiency
        int maxHighlights = config.getConfigSettings().getMaxHighlightsPerSecret();
        
        try {
            // Use ByteArray instead of String for better performance
            burp.api.montoya.core.ByteArray responseBytes = response.toByteArray();
            config.appendToLog("Scanning response of " + responseBytes.length() + " bytes with " + secretPatterns.size() + " patterns");
            
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
                    config.appendToLog("Testing pattern: " + pattern.getName());
                    
                    if ((pattern.getName().equals("Generic Secret") || pattern.getName().equals("Generic Secret v2")) && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        config.appendToLog("Skipping " + pattern.getName() + " - randomness algorithm disabled");
                        continue;
                    }

                    // Use ByteArray's native indexOf method for pattern matching
                    int searchFrom = 0;
                    int patternsFound = 0;
                    
                    MatchResult matchResult;
                    while ((matchResult = findPatternBounds(responseBytes, pattern.getPattern(), searchFrom)) != null) {
                        patternsFound++;
                        config.appendToLog("Pattern '" + pattern.getName() + "' found at position " + matchResult.startPos + "-" + matchResult.endPos);
                        
                        // Extract only the matched portion for group extraction
                        ByteArray matchedBytes = responseBytes.subArray(matchResult.startPos, matchResult.endPos);
                        String matchedString = matchedBytes.toString();
                        
                        java.util.regex.Matcher matcher = pattern.getPattern().matcher(matchedString);
                        
                        // The entire string should match since we extracted exactly the match
                        if (matcher.find()) {
                            // Extract group info
                            if ((pattern.getName().equals("Generic Secret") || pattern.getName().equals("Generic Secret v2")) && matcher.groupCount() >= 1) {
                                secretValue = matcher.group(1);
                                config.appendToLog("Extracted secret value for " + pattern.getName() + ": " + secretValue.substring(0, Math.min(10, secretValue.length())) + "...");
                                
                                // Skip non-random strings etc.
                                if (!RandomnessAlgorithm.isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                    config.appendToLog("Skipping non-random string for " + pattern.getName());
                                    // Continue searching from after this match
                                    searchFrom = matchResult.endPos;
                                    continue;
                                }
                                
                                // Skip if the Generic Secret matches reCAPTCHA Site Key pattern
                                if (isRecaptchaSecret(secretValue)) {
                                    config.appendToLog("Skipping reCAPTCHA secret for " + pattern.getName());
                                    // Continue searching from after this match
                                    searchFrom = matchResult.endPos;
                                    continue;
                                }
                            } else {
                                // Use capture group if available to avoid boundary characters
                                if (matcher.groupCount() >= 1) {
                                    secretValue = matcher.group(1);
                                } else {
                                    secretValue = matcher.group(0);
                                }
                                config.appendToLog("Extracted secret value for " + pattern.getName() + ": " + secretValue.substring(0, Math.min(10, secretValue.length())) + "...");
                            }
                            
                            // Skip duplicates (but still add to set for tracking)
                            if (uniqueSecretValues.contains(secretValue)) {
                                config.appendToLog("Skipping duplicate secret value");
                                // Continue searching from after this match
                                searchFrom = matchResult.endPos;
                                continue;
                            }
                            uniqueSecretValues.add(secretValue);
                            
                            // Find all occurrences of this secret in the response using ByteArray methods
                            searchStart = 0;
                            highlightsCreated = 0;
                            
                            while (searchStart < responseBytes.length() && highlightsCreated < maxHighlights) {
                                // Use ByteArray's indexOf for better performance
                                exactPos = responseBytes.indexOf(secretValue, true, searchStart, responseBytes.length());
                                
                                if (exactPos == -1) {
                                    break; // No more occurrences
                                }
                                
                                config.appendToLog("Found occurrence of secret at position " + exactPos + " (highlight " + (highlightsCreated + 1) + "/" + maxHighlights + ")");
                                
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
                            if (highlightsCreated >= maxHighlights && searchStart < responseBytes.length()) {
                                int remainingPos = responseBytes.indexOf(secretValue, true, searchStart, responseBytes.length());
                                if (remainingPos != -1) {
                                    config.appendToLog(String.format("Limited highlights for secret '%s' to %d (more occurrences exist but not highlighted for performance)", 
                                        secretValue.substring(0, Math.min(10, secretValue.length())) + "...", maxHighlights));
                                }
                            }
                        } else {
                            config.appendToLog("Could not find match in extracted string for " + pattern.getName());
                        }
                        
                        // Continue searching from after this match
                        searchFrom = matchResult.endPos;
                    }
                    
                    config.appendToLog("Pattern '" + pattern.getName() + "' completed. Found " + patternsFound + " matches");
                    
                } catch (Exception e) {
                    config.appendToLog("Error with pattern " + pattern.getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            config.appendToLog("Scan completed. Found " + foundSecrets.size() + " total secrets");
            
        } catch (Exception e) {
            config.appendToLog("Error scanning response: " + e.getMessage());
            e.printStackTrace();
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