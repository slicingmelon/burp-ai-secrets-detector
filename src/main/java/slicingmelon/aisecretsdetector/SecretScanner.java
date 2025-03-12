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
    
    private final MontoyaApi api;
    private final List<SecretPattern> secretPatterns;
    private static final String RANDOM_STRING_REGEX = "(?i:key|token|secret|password)\\w*[\"']?]?\\s*(?:[:=]|:=|=>|<-)\\s*[\\t \"'`]?([\\w+./=~-]{15,80})(?:[\\t\\n \"'`]|$)";
    //private static final String RANDOM_STRING_REGEX = "(?i:key|token|secret|password)\\w*[\"']?]?\\s*(?:[:=]|:=|=>|<-|:\\s+\")\\s*[\\t \"'`]?([\\w+./=~-]{15,80})(?:[\\t\\n \"'`]|$)";

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
        private final boolean requiresRandomCheck;
        
        public SecretPattern(String name, Pattern pattern, boolean requiresRandomCheck) {
            this.name = name;
            this.pattern = pattern;
            this.requiresRandomCheck = requiresRandomCheck;
        }
        
        public String getName() {
            return name;
        }
        
        public Pattern getPattern() {
            return pattern;
        }
        
        public boolean requiresRandomCheck() {
            return requiresRandomCheck;
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
        
        // URL with credentials
        patterns.add(new SecretPattern(
                "URL with Credentials",
                Pattern.compile("[A-Za-z]+://\\S{3,50}:(\\S{3,50})@[\\dA-Za-z#%&+./:=?_~-]+"),
                false
        ));

        patterns.add(new SecretPattern(
            "AWS Access Key",
            Pattern.compile("\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,20})\\b"),
            false
        ));
        
        // JWT/JWE
        patterns.add(new SecretPattern(
                "JWT/JWE Token",
                Pattern.compile("\\beyJ[\\dA-Za-z=_-]+(?:\\.[\\dA-Za-z=_-]{3,}){1,4}"),
                false
        ));
        
        // GitHub PAT
        patterns.add(new SecretPattern(
                "GitHub Personal Access Token",
                Pattern.compile("(?:gh[oprsu]|github_pat)_[\\dA-Za-z_]{36}"),
                false
        ));
        
        // GitLab Token
        patterns.add(new SecretPattern(
                "GitLab Token",
                Pattern.compile("glpat-[\\dA-Za-z_=-]{20,22}"),
                false
        ));
        
        // Stripe API Key
        patterns.add(new SecretPattern(
                "Stripe API Key",
                Pattern.compile("[rs]k_live_[\\dA-Za-z]{24,247}"),
                false
        ));
        
        // Square OAuth Secret
        patterns.add(new SecretPattern(
                "Square OAuth Secret",
                Pattern.compile("sq0i[a-z]{2}-[\\dA-Za-z_-]{22,43}"),
                false
        ));
        
        // Square Access Token
        patterns.add(new SecretPattern(
                "Square Access Token",
                Pattern.compile("sq0c[a-z]{2}-[\\dA-Za-z_-]{40,50}"),
                false
        ));
        
        // Square Access Token
        patterns.add(new SecretPattern(
            "Square Access Token",
            Pattern.compile("\\bEAAA[\\dA-Za-z+=-]{60}\\b"),
            false
    ));
        
        // Azure Storage Account Key
        patterns.add(new SecretPattern(
                "Azure Storage Account Key",
                Pattern.compile("AccountKey=[\\d+/=A-Za-z]{88}"),
                false
        ));
        
        // GCP API Key
        patterns.add(new SecretPattern(
                "GCP API Key",
                Pattern.compile("AIzaSy[\\dA-Za-z_-]{33}"),
                false
        ));
        
        // NPM Token (modern)
        patterns.add(new SecretPattern(
                "NPM Token (modern)",
                Pattern.compile("npm_[\\dA-Za-z]{36}"),
                false
        ));
        
        // NPM Token (legacy)
        patterns.add(new SecretPattern(
                "NPM Token (legacy)",
                Pattern.compile("//.+/:_authToken=[\\dA-Za-z_-]+"),
                false
        ));
        
        // Slack Token
        patterns.add(new SecretPattern(
                "Slack Token",
                Pattern.compile("xox[aboprs]-(?:\\d+-)+[\\da-z]+"),
                false
        ));
        
        // Slack Webhook URL
        patterns.add(new SecretPattern(
                "Slack Webhook URL",
                Pattern.compile("https://hooks\\.slack\\.com/services/T[\\dA-Za-z_]+/B[\\dA-Za-z_]+/[\\dA-Za-z_]+"),
                false
        ));
        
        // SendGrid API Key
        patterns.add(new SecretPattern(
                "SendGrid API Key",
                Pattern.compile("SG\\.[\\dA-Za-z_-]{22}\\.[\\dA-Za-z_-]{43}"),
                false
        ));
        
        // Twilio API Key
        patterns.add(new SecretPattern(
                "Twilio API Key",
                Pattern.compile("(?:AC|SK)[\\da-z]{32}"),
                false
        ));
        
        // Mailchimp API Key
        patterns.add(new SecretPattern(
                "Mailchimp API Key",
                Pattern.compile("[\\da-f]{32}-us\\d{1,2}"),
                false
        ));
        
        // Intra42 Secret
        patterns.add(new SecretPattern(
                "Intra42 Secret",
                Pattern.compile("s-s4t2(?:af|ud)-[\\da-f]{64}"),
                false
        ));
                
        // Age Secret Key
        patterns.add(new SecretPattern(
                "Age Secret Key",
                Pattern.compile("AGE-SECRET-KEY-1[\\dA-Z]{58}"),
                false
        ));
        
        // Generic Private Key (RSA, DSA, etc.)
        patterns.add(new SecretPattern(
            "Private Key",
            Pattern.compile("(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----"),
            false
        ));
        
        // Generic Secret (Random String)
        patterns.add(new SecretPattern(
                "Generic Secret",
                Pattern.compile(RANDOM_STRING_REGEX),
                true
        ));
        
        return patterns;
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
                            
                            // Check if this is actually a random string
                            if (pattern.requiresRandomCheck() && !isRandom(secretValue.getBytes(StandardCharsets.UTF_8))) {
                                continue;  // Skip if not random enough
                            }
                        } else {
                            // For other patterns, use the whole match
                            secretValue = matcher.group(0);
                            bodyStartPos = matcher.start(0);
                            bodyEndPos = matcher.end(0);
                        }
                        
                        // Skip if we've already found this secret value in this response
                        if (uniqueSecretValues.contains(secretValue)) {
                            api.logging().logToOutput("Skipping duplicate secret: " + secretValue);
                            continue;
                        }
                        
                        uniqueSecretValues.add(secretValue);
                        
                        // Convert body positions to full response positions by adding bodyOffset
                        int fullStartPos = bodyOffset + bodyStartPos;
                        int fullEndPos = bodyOffset + bodyEndPos;
                        
                        // Calculate highlight positions with 20 character buffer for better visibility
                        int highlightStart = Math.max(bodyOffset, fullStartPos - 20);
                        int highlightEnd = Math.min(bodyOffset + responseBody.length(), fullEndPos + 20);
                        
                        Secret secret = new Secret(pattern.getName(), secretValue, highlightStart, highlightEnd);
                        foundSecrets.add(secret);
                        
                        // api.logging().logToOutput(String.format(
                        //     "Found %s: '%s' at body position %d-%d (highlight: %d-%d)",
                        //     pattern.getName(), secretValue, bodyStartPos, bodyEndPos, highlightStart, highlightEnd
                        // ));
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
    
    /**
     * Determines if a byte sequence is likely to be a random string (secret)
     * Ported from RipSecrets p_random.rs
     */
    private boolean isRandom(byte[] data) {
        // Check if the data is valid
        if (data == null || data.length < 15) {
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
        double base = isHex(data) ? 16.0 : 64.0;
        
        double p = pRandomDistinctValues(data, base) * pRandomCharClass(data, base);
        
        // Bigram analysis only works reliably for base64
        if (base == 64.0) {
            p *= pRandomBigrams(data);
        }
        
        return p;
    }
    
    /**
     * Checks if a byte sequence appears to be hexadecimal
     */
    private boolean isHex(byte[] data) {
        for (byte b : data) {
            if (!((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F'))) {
                return false;
            }
        }
        return data.length >= 16;
    }
    
    /**
     * Analyzes character classes to determine randomness
     */
    private double pRandomCharClass(byte[] data, double base) {
        if (base == 16.0) {
            return pRandomCharClassAux(data, (byte)'0', (byte)'9', 16.0);
        } else {
            double minP = Double.POSITIVE_INFINITY;
            byte[][] charClasses = {{(byte)'0', (byte)'9'}, {(byte)'A', (byte)'Z'}, {(byte)'a', (byte)'z'}};
            
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