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
* Utility class for SecretScanner
*/
public class SecretScannerUtils {
    // Random string pattern
    public static final String RANDOM_STRING_REGEX_TEMPLATE = "(?i:auth|key|token|secret|passwd|password)\\w*[\"']?]?\\s*(?:[:=]|:=|=>|<-)\\s*[\\t \"'`]?([\\w+./=~-]{%d,80})(?:[\\t\\n \"'`]|$)";

    private static final List<SecretScanner.SecretPattern> SECRET_PATTERNS = new ArrayList<>();
    private static int genericSecretMinLength = 15;

    /**
    * Set the minimum length for generic secrets (random algorithm matcher) and regenerate patterns
    * @param length The new minimum length
    */
    public static void setGenericSecretMinLength(int length) {
        if (length != genericSecretMinLength) {
            genericSecretMinLength = length;
            // Regenerate the patterns
            SECRET_PATTERNS.clear();
            initializePatterns();
        }
    }

    /**
    * Get the current minimum generic secret length
    * @return The minimum generic secret length
    */
    public static int getGenericSecretMinLength() {
        return genericSecretMinLength;
    }

    // Load and compile patterns
    static {
        initializePatterns();
    }

    // Load and compile patterns during load time
    // Credits to gitleaks for most of the fixed patterns regexes
    private static void initializePatterns() {
        // URL with Credentials
        addPattern("URL with Credentials", 
            "(?i)\\b[a-zA-Z]+://(?:[A-Za-z0-9_-]{1,32}):(?:[^@{}|^\\\\[\\\\]`]+)@([a-zA-Z0-9.-]+)(?:/[^/\\s]*)?\\b");
        
        // Age Secret Key
        addPattern("Age Secret Key", 
            "AGE-SECRET-KEY-1[\\dA-Z]{58}");

        addPattern("Algolia API Key", 
        "(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("Azure Storage Account Key", 
            "AccountKey=[\\d+/=A-Za-z]{88}");
        
        addPattern("Azure AD Client Secret", 
            "(?:^|[\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'\"\\x60\\s<),])");
        
        addPattern("AWS Access Key", 
            "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,20})\\b");
        
        addPattern("Fastly API Key", 
            "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("GitHub Personal Access Token", 
            "(?:gh[oprsu]|github_pat)_[\\dA-Za-z_]{36}");
        
        addPattern("GitLab Token", 
            "glpat-[\\dA-Za-z_=-]{20,22}");
        
        addPattern("Cloudflare API Key", 
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("Cloudflare Global API Key", 
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("GCP API Key", 
            "AIzaSy[\\dA-Za-z_-]{33}");
        
        addPattern("JWT/JWE Token", 
            "\\beyJ[\\dA-Za-z=_-]+(?:\\.[\\dA-Za-z=_-]{3,}){1,4}");
        
        addPattern("Mailgun Signing Key", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("Mailgun Private API Token", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("OpenAI API Key", 
            "\\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("NPM Token (modern)", 
            "npm_[\\dA-Za-z]{36}");
        
        addPattern("NPM Token (legacy)", 
            "//.+/:_authToken=[\\dA-Za-z_-]+");

        // reCAPTCHA Site Key
        addPattern("reCAPTCHA Site Key", 
            "\\b6[LM][a-zA-Z0-9_-]{38}\\b");
        
        // reCAPTCHA Secret Key
        addPattern("reCAPTCHA Secret Key", 
            "\\b6[LM][a-zA-Z0-9_-]{39}\\b");
        
        addPattern("Slack Token", 
            "xox[aboprs]-(?:\\d+-)+[\\da-z]+");
        
        addPattern("Slack Config Access Token", 
            "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}");
        
        addPattern("Slack Legacy Workspace Token", 
            "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}");
        
        addPattern("Slack Webhook URL", 
            "(?:https?://)?hooks.slack.com/(?:services|workflows)/[A-Za-z0-9+/]{43,46}");
        
        addPattern("SendGrid API Key", 
            "SG\\.[\\dA-Za-z_-]{22}\\.[\\dA-Za-z_-]{43}");
        
        addPattern("Stripe API Key", 
            "[rs]k_live_[\\dA-Za-z]{24,247}");
        
        addPattern("Square Access Token", 
            "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("Squarespace Access Token", 
            "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)");
        
        addPattern("Twilio API Key", 
            "(?:AC|SK)[\\da-z]{32}");
        
        addPattern("Mailchimp API Key", 
            "[\\da-f]{32}-us\\d{1,2}");
        
        addPattern("Intra42 Secret", 
            "s-s4t2(?:af|ud)-[\\da-f]{64}");
        
        addPattern("Generic Private Key", 
            "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----");
        
        // Generic Secret pattern
        String randomStringRegex = String.format(RANDOM_STRING_REGEX_TEMPLATE, genericSecretMinLength);
        addPattern("Generic Secret", randomStringRegex);
    }
    
    /**
    * Helper method to compile and store a pattern with its metadataa
    */
    private static void addPattern(String name, String regex) {
        SECRET_PATTERNS.add(new SecretScanner.SecretPattern(
            name, Pattern.compile(regex)));
    }
    
    /**
    * Get all precompiled secret patterns
    * @return List of SecretPattern objects
    */
    public static List<SecretScanner.SecretPattern> getAllPatterns() {
        return SECRET_PATTERNS;
    }
}