/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Utility class for SecretScanner - now uses Config class for patterns
 */
public class SecretScannerUtils {
    
    /**
     * Helper function similar to TruffleHog's PrefixRegex
     * Creates a case-insensitive prefix pattern that allows up to 40 characters between keyword and secret
     * @param keywords Array of keywords to match (e.g., ["cloudflare", "cf"])
     * @return Regex string for prefix matching
     */
    public static String buildPrefixRegex(String[] keywords) {
        return buildPrefixRegex(keywords, 40);
    }
    
    /**
     * Helper function similar to TruffleHog's PrefixRegex with configurable max prefix length
     * Creates a case-insensitive prefix pattern that allows up to maxPrefixLen characters between keyword and secret
     * @param keywords Array of keywords to match (e.g., ["cloudflare", "cf"])
     * @param maxPrefixLen Maximum number of characters allowed between keyword and secret
     * @return Regex string for prefix matching
     */
    public static String buildPrefixRegex(String[] keywords, int maxPrefixLen) {
        String pre = "(?i:";
        String middle = String.join("|", keywords);
        String post = ")(?:.|[\\n\\r\\t]){0," + maxPrefixLen + "}?";
        return pre + middle + post;
    }
    
    public static String buildPrefixRegexRIP(String[] keywords) {
        String keywordGroup = String.join("|", keywords);
    
        // Build non-capturing, case-insensitive keyword prefix with flexible key tail
        StringBuilder regex = new StringBuilder();
    
        regex.append("(?i:")  // Case-insensitive group
             .append(keywordGroup)
             .append(")")     // end non-capturing keyword group
             .append("\\w*")  // allow keyID, tokenName, etc.
             .append("[\"']?]?") // optional trailing quote or bracket after key
             .append("\\s*")  // optional whitespace before separator
             .append("(?:[:=]|:=|=>|<-|>)")  // assignment operators
             .append("\\s*")  // optional whitespace after separator
             .append("(?:\\\\?[\\" + "\"" + "'])?"); // escaped or unescaped quote (\\?["'])
    
        return regex.toString();
    }
    
    /**
     * Helper function to create suffix boundary patterns for secret detection
     * Creates a non-capturing group that matches common secret terminators including escaped JSON scenarios
     * Inspired by gitleaks patterns with additional web/JSON-specific boundaries
     * @return Regex string for suffix boundary matching
     */
    public static String buildSuffixRegex() {
        // Match common terminators: whitespace, quotes, backticks, semicolons, escaped whitespace chars, escaped quotes, HTML/XML tags, end of string
        return "(?:[\\x60'\"\\s;]|\\\\[nrt]|\\\\\"|</|$)";
    }

    public static String buildSuffixRegexRIP() {
        // Match common terminators: whitespace, quotes, backticks, semicolons, escaped whitespace chars, escaped quotes, HTML/XML tags, end of string
        return "(?:[\\x60'\"\\s;]|\\\\[nrt]|\\\\\"|</|$)";
    }

    /**
    * Check if the randomness algorithm detection is enabled
    * @return True if enabled, false otherwise
    */
    public static boolean isRandomnessAlgorithmEnabled() {
        Config config = Config.getInstance();
        return config != null && config.getSettings().isRandomnessAlgorithmEnabled();
    }

    /**
    * Get the current minimum generic secret length
    * @return The minimum generic secret length
    */
    public static int getGenericSecretMinLength() {
        Config config = Config.getInstance();
        return config != null ? config.getSettings().getGenericSecretMinLength() : 15;
    }

    /**
    * Get the current maximum generic secret length
    * @return The maximum generic secret length
    */
    public static int getGenericSecretMaxLength() {
        Config config = Config.getInstance();
        return config != null ? config.getSettings().getGenericSecretMaxLength() : 80;
    }


    
    /**
    * Get all precompiled secret patterns from Config
    * @return List of SecretPattern objects
    */
    public static List<SecretScanner.SecretPattern> getAllPatterns() {
        Config config = Config.getInstance();
        if (config == null) {
            return new ArrayList<>();
        }
        
        List<SecretScanner.SecretPattern> patterns = new ArrayList<>();
        
        for (Config.PatternConfig patternConfig : config.getPatterns()) {
            patterns.add(new SecretScanner.SecretPattern(
                patternConfig.getName(), 
                patternConfig.getCompiledPattern()
            ));
        }
        
        return patterns;
    }
    
    /**
     * Update excluded file extensions from Config
     * @param fileExtension The file extension to check
     * @return True if the file extension should be skipped
     */
    public static boolean shouldSkipFileExtension(String fileExtension) {
        Config config = Config.getInstance();
        if (config == null) {
            return false;
        }
        
        return config.getSettings().getExcludedFileExtensions().contains(fileExtension.toLowerCase());
    }
}