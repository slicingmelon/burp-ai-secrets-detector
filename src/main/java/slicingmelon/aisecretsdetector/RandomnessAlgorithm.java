/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.core.ByteArray;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Randomness detection algorithm ported from RipSecrets
 * Used to determine if a byte sequence is likely to be a random string (secret)
 */
public class RandomnessAlgorithm {
    
    // Memoization cache for configuration calculations
    private static final Map<String, Double> configCache = new HashMap<>();
    
    /**
     * Determines if a byte sequence is likely to be a random string (secret)
     * Ported from RipSecrets p_random.rs
     */
    public static boolean isRandom(ByteArray data) {
        // Check if the data is valid
        if (data == null || data.length() < SecretScannerUtils.getGenericSecretMinLength()) {
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
    private static double pRandom(ByteArray data) {
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
    private static boolean isHex(ByteArray data) {
        if (data.length() < 16) {
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
    private static boolean isCapAndNumbers(ByteArray data) {
        if (data.length() < 16) {
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
    private static double pRandomCharClass(ByteArray data, double base) {
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
    private static double pRandomCharClassAux(ByteArray data, byte min, byte max, double base) {
        int count = 0;
        for (byte b : data) {
            if (b >= min && b <= max) {
                count++;
            }
        }
        
        double numChars = (max - min + 1);
        return pBinomial(data.length(), count, numChars / base);
    }
    
    /**
     * Calculates binomial probability
     */
    private static double pBinomial(int n, int x, double p) {
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
    private static double factorial(int n) {
        double result = 1.0;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }
    
    /**
     * Calculates randomness based on bigram frequencies
     */
    private static double pRandomBigrams(ByteArray data) {
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
        for (int i = 0; i < data.length() - 1; i++) {
            String bigram = data.subArray(i, i + 2).toString();
            if (bigramSet.contains(bigram)) {
                numBigrams++;
            }
        }
        
        return pBinomial(data.length() - 1, numBigrams, (double) bigramSet.size() / (64.0 * 64.0));
    }
    
    /**
     * Calculates randomness probability based on distinct values
     */
    private static double pRandomDistinctValues(ByteArray data, double base) {
        double totalPossible = Math.pow(base, data.length());
        int numDistinctValues = countDistinctValues(data);
        
        double numMoreExtremeOutcomes = 0.0;
        for (int i = 1; i <= numDistinctValues; i++) {
            numMoreExtremeOutcomes += numPossibleOutcomes(data.length(), i, (int) base);
        }
        
        return numMoreExtremeOutcomes / totalPossible;
    }
    
    /**
     * Counts distinct values in a byte array
     */
    private static int countDistinctValues(ByteArray data) {
        Set<Byte> values = new HashSet<>();
        for (byte b : data) {
            values.add(b);
        }
        return values.size();
    }
    
    /**
     * Calculates number of possible outcomes
     */
    private static double numPossibleOutcomes(int numValues, int numDistinctValues, int base) {
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
    private static double numDistinctConfigurations(int numValues, int numDistinctValues) {
        if (numDistinctValues == 1 || numDistinctValues == numValues) {
            return 1.0;
        }
        return numDistinctConfigurationsAux(numDistinctValues, 0, numValues - numDistinctValues);
    }
    
    /**
     * Recursive helper for distinct configurations calculation
     * Memoized version of the function from ripsecrets
     */
    private static double numDistinctConfigurationsAux(int numPositions, int position, int remainingValues) {
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