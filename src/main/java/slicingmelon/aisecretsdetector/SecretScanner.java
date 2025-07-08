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
//import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;

public class SecretScanner {
    private final Config config;
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
    // public static class MatchResult {
    //     public final int startPos;
    //     public final int endPos;
        
    //     public MatchResult(int startPos, int endPos) {
    //         this.startPos = startPos;
    //         this.endPos = endPos;
    //     }
    // }
    
    /**
     * Find pattern match bounds in ByteArray and return both start and end positions
     * @param data ByteArray to search in
     * @param pattern Pattern to search for
     * @param startIndex Where to start searching
     * @return MatchResult with start and end positions, or null if no match found
     */
    // private static MatchResult findPatternBounds(ByteArray data, Pattern pattern, int startIndex) {
    //     // First, find the match position using ByteArray's indexOf
    //     int matchStart = data.indexOf(pattern, startIndex, data.length());
    //     if (matchStart == -1) {
    //         return null;
    //     }

    //     // Adjust buffer size for known long patterns like private keys
    //     int bufferSize = 300; // Default buffer
    //     if (pattern.pattern().contains("PRIVATE KEY")) {
    //         bufferSize = 4096; // Use a larger buffer for private keys
    //     }
        
    //     // To find the end position, we need to apply the regex to a small portion
    //     // Extract a reasonable chunk around the match (but not too much to avoid overflow)
    //     int extractStart = Math.max(0, matchStart - 10); // Small buffer before
    //     int extractEnd = Math.min(data.length(), matchStart + bufferSize); // Reasonable buffer after
        
    //     try {
    //         ByteArray matchRegion = data.subArray(extractStart, extractEnd);
    //         String matchRegionString = matchRegion.toString();
            
    //         Matcher matcher = pattern.matcher(matchRegionString);
            
    //         // Find the match in the extracted region
    //         int regionMatchPos = matchStart - extractStart;
    //         if (matcher.find(regionMatchPos)) {
    //             // Calculate actual positions in the original ByteArray
    //             int actualStart = extractStart + matcher.start();
    //             int actualEnd = extractStart + matcher.end();
    //             return new MatchResult(actualStart, actualEnd);
    //         }
    //     } catch (Exception e) {
    //         // Fallback: assume the match is at least 1 character
    //         return new MatchResult(matchStart, matchStart + 1);
    //     }
        
    //     return null;
    // }
    
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
        Config configInstance;
        
        try {
            //this.api = api;
            patterns = SecretScannerUtils.getAllPatterns();
            configInstance = Config.getInstance();
            
            AISecretsDetector.getInstance().logMsg("SecretScanner initialized with " + patterns.size() + " patterns");
        } catch (Exception e) {
            AISecretsDetector.getInstance().logMsgError("Error initializing SecretScanner: " + e.getMessage());
            e.printStackTrace();
            patterns = new ArrayList<>(); // fallback to empty list
            configInstance = Config.getInstance();
        }
        
        this.secretPatterns = patterns;
        this.config = configInstance;
    }
    
    public SecretScanResult scanResponse(HttpResponse response) {
        List<Secret> foundSecrets = new ArrayList<>();
        Map<String, Set<String>> uniqueSecretsPerPattern = new HashMap<>();
        
        int maxHighlights = config.getSettings().getMaxHighlightsPerSecret();
        
        try {
            // Use String for reliable regex matching
            String responseString = response.toString();
            // Use ByteArray for fast, byte-accurate searching of found secrets
            ByteArray responseBytes = response.toByteArray();
            // Log through the detector instance
            
            // Declare variables outside loops for efficiency
            String secretValue;
            Secret secret;
            
            for (SecretPattern pattern : secretPatterns) {
                try {
                    // Testing pattern: pattern.getName()
                    
                    if ((pattern.getName().equals("Generic Secret") || pattern.getName().equals("Generic Secret v2")) && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        // Skipping pattern - randomness algorithm disabled
                        continue;
                    }

                    Matcher matcher = pattern.getPattern().matcher(responseString);
                    
                    while (matcher.find()) {
                        // STEP 1: IDENTIFY secret value using Java's regex engine (Burp's API indexOf pattern not working properly)
                        if ((pattern.getName().equals("Generic Secret") || pattern.getName().equals("Generic Secret v2")) && matcher.groupCount() >= 1) {
                            secretValue = matcher.group(1);
                            // Extracted potential secret for pattern
                            
                            if (!RandomnessAlgorithm.isRandom(ByteArray.byteArray(secretValue))) {
                                // Skipping non-random string
                                continue;
                            }
                            
                            if (isRecaptchaSecret(secretValue)) {
                                // Skipping reCAPTCHA secret
                                continue;
                            }
                        } else {
                            // Use capture group if available to avoid boundary characters
                            if (matcher.groupCount() >= 1) {
                                secretValue = matcher.group(1);
                            } else {
                                secretValue = matcher.group(0); // Whole match
                            }
                            // Extracted secret value for pattern
                        }

                        // STEP 2: CHECK FOR UNIQUENESS for this pattern
                        // If we have already found and highlighted this exact secret value for this pattern, skip to the next match.
                        Set<String> foundValuesForPattern = uniqueSecretsPerPattern.computeIfAbsent(pattern.getName(), _ -> new HashSet<>());
                        if (!foundValuesForPattern.add(secretValue)) {
                            continue;
                        }
                        
                        // Found new unique secret for pattern

                        // STEP 3: LOCATE all occurrences using ByteArray.indexOf, as it's supposedly faster.
                        int searchStart = 0;
                        int highlightsCreated = 0;
                        ByteArray secretValueBytes = ByteArray.byteArray(secretValue);

                        while (highlightsCreated < maxHighlights) {
                            int exactPos = responseBytes.indexOf(secretValueBytes, true, searchStart, responseBytes.length());

                            if (exactPos == -1) {
                                break;
                            }

                            // Create a secret for this occurrence
                            int fullStartPos = exactPos;
                            int fullEndPos = fullStartPos + secretValueBytes.length();
                            secret = new Secret(pattern.getName(), secretValue, fullStartPos, fullEndPos);
                            foundSecrets.add(secret);
                            highlightsCreated++;

                            // Move search start past this occurrence
                            searchStart = fullEndPos;
                        }
                    }
                } catch (Exception e) {
                    // Error with pattern
                    e.printStackTrace();
                }
            }
            
            // Scan completed with foundSecrets.size() total secrets
            
        } catch (Exception e) {
            // Error scanning response
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