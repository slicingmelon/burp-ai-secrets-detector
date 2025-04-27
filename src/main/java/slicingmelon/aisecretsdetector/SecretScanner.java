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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.nio.charset.StandardCharsets;

public class SecretScanner {
    private final Config config;

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
        //this.api = api;
        this.secretPatterns = SecretScannerUtils.getAllPatterns();
        this.config = Config.getInstance();
    }
    
    public SecretScanResult scanResponse(HttpResponse response) {
        List<Secret> foundSecrets = new ArrayList<>();
        
        // Track unique secrets by value to avoid duplicates within the same response
        Set<String> uniqueSecretValues = new HashSet<>();
        
        try {
            String responseBody = response.bodyToString();
            
            int bodyOffset = response.bodyOffset();
            
            for (SecretPattern pattern : secretPatterns) {
                try {

                    // Skip reCAPTCHA Site Key pattern - we only want reCAPTCHA Secret Keys
                    if (pattern.getName().equals("reCAPTCHA Site Key")) {
                        continue;
                    }

                    // Skip randomness algorithm detection if disabled in settings
                    if (pattern.getName().equals("Generic Secret") && !SecretScannerUtils.isRandomnessAlgorithmEnabled()) {
                        config.appendToLog("Skipping Generic Secret pattern - randomness algorithm disabled");
                        continue;
                    }

                    Matcher matcher = pattern.getPattern().matcher(responseBody);
                    
                    while (matcher.find()) {
                        String secretValue;
                        int bodyStartPos; 
                        int bodyEndPos;
                        
                        if (pattern.getName().equals("Generic Secret") && matcher.groupCount() >= 1) {
                            // For the random string pattern, we only want to extract the actual secret (group 1)
                            secretValue = matcher.group(1);
                            bodyStartPos = matcher.start(1);
                            bodyEndPos = matcher.end(1);

                            // Check if this is a reCAPTCHA Site Key by directly using the pattern
                            // We want to skip reCAPTCHA Site Key, as it's useless
                            boolean isReCaptchaSiteKey = false;
                            for (SecretPattern p : secretPatterns) {
                                if (p.getName().equals("reCAPTCHA Site Key") && p.getPattern().matcher(secretValue).matches()) {
                                    isReCaptchaSiteKey = true;
                                    config.appendToLog("Skipping reCAPTCHA Site Key detected by Generic Secret pattern: " + secretValue);
                                    break;
                                }
                            }
                            
                            // Skip this match if it's a reCAPTCHA Site Key
                            if (isReCaptchaSiteKey) {
                                continue;
                            }

                            // Check if this is actually a random string
                            if (!isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                continue;  // Skip if not random enough
                            }

                        } else {
                            // For other patterns, use the whole match
                            secretValue = matcher.group(0);
                            bodyStartPos = matcher.start(0);
                            bodyEndPos = matcher.end(0);
                        }
                        
                        // Skip if we've already found this secret value in this response
                        // Could kill burp easily
                        if (uniqueSecretValues.contains(secretValue)) {
                            config.appendToLog("Skipping duplicate secret: " + secretValue);
                            continue;
                        }
                        
                        uniqueSecretValues.add(secretValue);
                        
                        // Convert body positions to full response positions by adding bodyOffset
                        int fullStartPos = bodyOffset + bodyStartPos;
                        int fullEndPos = bodyOffset + bodyEndPos;
                        
                        // Calculate highlight positions with 20 character buffer for better visibility
                        // int highlightStart = Math.max(bodyOffset, fullStartPos - 20);
                        // int highlightEnd = Math.min(bodyOffset + responseBody.length(), fullEndPos + 20);
                        int highlightStart = fullStartPos;
                        int highlightEnd = fullEndPos;
                        
                        Secret secret = new Secret(pattern.getName(), secretValue, highlightStart, highlightEnd);
                        foundSecrets.add(secret);
                        
                        config.appendToLog(String.format(
                            "Found %s: '%s' at body position %d-%d (highlight: %d-%d)",
                            pattern.getName(), secretValue, bodyStartPos, bodyEndPos, highlightStart, highlightEnd
                        ));
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
    * Determines if a byte sequence is likely to be a random string (secret)
    * Ported from RipSecrets p_random.rs
    */
    private boolean isRandom(byte[] data) {
        // Check if the data is valid
        if (data == null || data.length < SecretScannerUtils.getGenericSecretMinLength()) {
            return false;
        }
        
        double p = pRandom(data);
        if (p < 1.0 / 1e5) {
            return false;
        }
        
        boolean containsDigit = false;
        for (byte b : data) {
            if (b >= '0' && b <= '9') {
                containsDigit = true;
                break;
            }
        }
        
        if (!containsDigit && p < 1.0 / 1e4) {
            return false;
        }
        
        return true;
    }

    /**
    * Calculates the probability that a byte sequence is random
    * Ported from RipSecrets
    */
    private double pRandom(byte[] data) {
        double base;
        if (isHex(data)) {
            base = 16.0;
        } else if (isCapAndNumbers(data)) {
            base = 36.0;
        } else {
            base = 64.0;
        }
        
        double p = pRandomDistinctValues(data, base) * pRandomCharClass(data, base);
        
        // Bigram analysis only works reliably for base64
        if (base == 64.0) {
            p *= pRandomBigrams(data);
        }
        
        return p;
    }
    
    /**
     * Checks if a byte sequence consists only of hex characters (0-9, a-f, A-F)
     * and is at least 16 bytes long
     */
    private boolean isHex(byte[] data) {
        if (data.length < 16) {
            return false;
        }
        
        for (byte b : data) {
            if (!((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    /**
    * Checks if a byte sequence consists only of capital letters and numbers (0-9, A-Z)
    * and is at least 16 bytes long
    */
    private boolean isCapAndNumbers(byte[] data) {
        if (data.length < 16) {
            return false;
        }
        
        for (byte b : data) {
            if (!((b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z'))) {
                return false;
            }
        }
        return true;
    }
    
    /**
    * Analyzes character classes to determine randomness
    */
    private double pRandomCharClass(byte[] data, double base) {
        if (base == 16.0) {
            return pRandomCharClassAux(data, (byte)'0', (byte)'9', 16.0);
        } else {
            double minP = Double.POSITIVE_INFINITY;
            
            byte[][] charClasses;
            if (base == 36.0) {
                // For base 36, we only check digits and uppercase
                charClasses = new byte[][] {{(byte)'0', (byte)'9'}, {(byte)'A', (byte)'Z'}};
            } else {
                // For base 64, we check digits, uppercase, and lowercase
                charClasses = new byte[][] {{(byte)'0', (byte)'9'}, {(byte)'A', (byte)'Z'}, {(byte)'a', (byte)'z'}};
            }
            
            for (byte[] charClass : charClasses) {
                double p = pRandomCharClassAux(data, charClass[0], charClass[1], base);
                if (p < minP) {
                    minP = p;
                }
            }
            
            return minP;
        }
    }
    
    /**
    * Calculates randomness probability for a specific character class
    */
    private double pRandomCharClassAux(byte[] data, byte min, byte max, double base) {
        int count = 0;
        for (byte b : data) {
            if (b >= min && b <= max) {
                count++;
            }
        }
        
        double numChars = (max - min + 1);
        return pBinomial(data.length, count, numChars / base);
    }
    
    /**
    * Calculates binomial probability
    */
    private double pBinomial(int n, int x, double p) {
        boolean leftTail = x < n * p;
        int min = leftTail ? 0 : x;
        int max = leftTail ? x : n;
        
        double totalP = 0.0;
        for (int i = min; i <= max; i++) {
            totalP += factorial(n) / (factorial(n - i) * factorial(i)) 
                    * Math.pow(p, i) 
                    * Math.pow(1.0 - p, n - i);
        }
        
        return totalP;
    }
    
    /**
    * Calculates factorial
    */
    private double factorial(int n) {
        double result = 1.0;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }
    
    /**
    * Calculates randomness based on bigram frequencies
    */
    private double pRandomBigrams(byte[] data) {
        // Common bigrams from ripsecrets code (a subset for Java version)
        String[] commonBigrams = {
            "er", "te", "an", "en", "ma", "ke", "10", "at", "/m", "on", 
            "09", "ti", "al", "io", ".h", "./", "..", "ra", "ht", "es", 
            "or", "tm", "pe", "ml", "re", "in", "3/", "n3", "0F", "ok", 
            "ey", "00", "80", "08", "ss", "07", "15", "81", "F3", "st"
        };
        
        Set<String> bigramSet = new HashSet<>();
        for (String bigram : commonBigrams) {
            bigramSet.add(bigram);
        }
        
        int numBigrams = 0;
        for (int i = 0; i < data.length - 1; i++) {
            String bigram = new String(data, i, 2, StandardCharsets.UTF_8);
            if (bigramSet.contains(bigram)) {
                numBigrams++;
            }
        }
        
        return pBinomial(data.length - 1, numBigrams, (double) bigramSet.size() / (64.0 * 64.0));
    }
    
    /**
    * Calculates randomness probability based on distinct values
    */
    private double pRandomDistinctValues(byte[] data, double base) {
        double totalPossible = Math.pow(base, data.length);
        int numDistinctValues = countDistinctValues(data);
        
        double numMoreExtremeOutcomes = 0.0;
        for (int i = 1; i <= numDistinctValues; i++) {
            numMoreExtremeOutcomes += numPossibleOutcomes(data.length, i, (int) base);
        }
        
        return numMoreExtremeOutcomes / totalPossible;
    }
    
    /**
    * Counts distinct values in a byte array
    */
    private int countDistinctValues(byte[] data) {
        Set<Byte> values = new HashSet<>();
        for (byte b : data) {
            values.add(b);
        }
        return values.size();
    }
    
    /**
    * Calculates number of possible outcomes
    */
    private double numPossibleOutcomes(int numValues, int numDistinctValues, int base) {
        double res = base;
        for (int i = 1; i < numDistinctValues; i++) {
            res *= (base - i);
        }
        res *= numDistinctConfigurations(numValues, numDistinctValues);
        return res;
    }
    
    /**
    * Calculates number of distinct configurations
    */
    private double numDistinctConfigurations(int numValues, int numDistinctValues) {
        if (numDistinctValues == 1 || numDistinctValues == numValues) {
            return 1.0;
        }
        return numDistinctConfigurationsAux(numDistinctValues, 0, numValues - numDistinctValues);
    }
    
    private final Map<String, Double> configCache = new HashMap<>();
    
    /**
    * Recursive helper for distinct configurations calculation
    * Memoized version of the function from ripsecrets
    */
    private double numDistinctConfigurationsAux(int numPositions, int position, int remainingValues) {
        String key = numPositions + ":" + position + ":" + remainingValues;
        if (configCache.containsKey(key)) {
            return configCache.get(key);
        }
        
        if (remainingValues == 0) {
            return 1.0;
        }
        
        double numConfigs = 0.0;
        if (position + 1 < numPositions) {
            numConfigs += numDistinctConfigurationsAux(numPositions, position + 1, remainingValues);
        }
        
        numConfigs += (position + 1) * numDistinctConfigurationsAux(numPositions, position, remainingValues - 1);
        
        configCache.put(key, numConfigs);
        return numConfigs;
    }
}