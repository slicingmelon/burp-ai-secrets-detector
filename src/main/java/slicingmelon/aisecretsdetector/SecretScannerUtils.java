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
import burp.api.montoya.logging.Logging;

/**
* Utility class for SecretScanner
*/
public class SecretScannerUtils {
    // Random string pattern (original)
    public static final String RANDOM_STRING_REGEX_TEMPLATE = "(?i:auth|credential|key|token|secret|pass|passwd|password)\\w*[\"']?]?\\s*(?:[:=]|:=|=>|<-|>)\\s*[\\t \"'`]?([\\w+./=~\\-\\\\`^]{%d,%d})(?=\\\\[\"']|[\\t\\n \"'`]|</|$)";
    
    // Random string pattern v2 (TruffleHog-style) - initialized in static block
    public static String RANDOM_STRING_REGEX_TEMPLATE2;

    private static final List<SecretScanner.SecretPattern> SECRET_PATTERNS = new ArrayList<>();
    private static Logging logging = null;
    
    /**
     * Set the logging instance for error reporting
     */
    public static void setLogging(Logging loggingInstance) {
        logging = loggingInstance;
    }
    
    /**
     * Helper function similar to TruffleHog's PrefixRegex
     * Creates a case-insensitive prefix pattern that allows up to 40 characters between keyword and secret
     * @param keywords Array of keywords to match (e.g., ["cloudflare", "cf"])
     * @return Regex string for prefix matching
     */
    public static String buildPrefixRegex(String[] keywords) {
        try {
            String pre = "(?i:";
            String middle = String.join("|", keywords);
            String post = ")(?:.|[\\n\\r\\t]){0,40}?";
            return pre + middle + post;
        } catch (Exception e) {
            if (logging != null) {
                logging.logToError("Error in buildPrefixRegex: " + e.getMessage());
            }
            return "(?i:error)"; // fallback
        }
    }
    
    private static int genericSecretMinLength = 15;
    private static int genericSecretMaxLength = 80;
    private static boolean randomnessAlgorithmEnabled = true;

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
    * Set the maximum length for generic secrets (random algorithm matcher) and regenerate patterns
    * @param length The new maximum length
    */
    public static void setGenericSecretMaxLength(int length) {
        if (length != genericSecretMaxLength) {
            genericSecretMaxLength = length;
            // Regenerate the patterns
            SECRET_PATTERNS.clear();
            initializePatterns();
        }
    }

    /**
    * Enable or disable the randomness algorithm detection
    * @param enabled Whether the algorithm should be enabled
    */
    public static void setRandomnessAlgorithmEnabled(boolean enabled) {
        randomnessAlgorithmEnabled = enabled;
    }

    /**
    * Check if the randomness algorithm detection is enabled
    * @return True if enabled, false otherwise
    */
    public static boolean isRandomnessAlgorithmEnabled() {
        return randomnessAlgorithmEnabled;
    }

    /**
    * Get the current minimum generic secret length
    * @return The minimum generic secret length
    */
    public static int getGenericSecretMinLength() {
        return genericSecretMinLength;
    }

    /**
    * Get the current maximum generic secret length
    * @return The maximum generic secret length
    */
    public static int getGenericSecretMaxLength() {
        return genericSecretMaxLength;
    }

    // Load and compile patterns
    static {
        try {
            // Initialize RANDOM_STRING_REGEX_TEMPLATE2 here to avoid circular dependency
            RANDOM_STRING_REGEX_TEMPLATE2 = buildPrefixRegex(new String[]{"auth", "credential", "key", "token", "secret", "pass", "passwd", "password"}) + "\\b([\\w+./=~\\-\\\\`\\^\\!\\@\\#\\$\\%\\&\\*\\(\\)\\_\\<\\>\\;]{%d,%d})\\b";
            
            initializePatterns();
        } catch (Exception e) {
            System.err.println("Critical error in SecretScannerUtils static initialization: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Load and compile patterns during load time
    // Credits to gitleaks for some of the fixed patterns regexes. These have been update to be more accurate.
    private static void initializePatterns() {
        // URL with Credentials
        addPattern("URL with Credentials", 
            "(?i)\\b([a-zA-Z]+://(?:[A-Za-z0-9_-]{1,32}):(?:[^@{}|^\\\\[\\\\]`]+)@[a-zA-Z0-9.-]+(?:/[^/\\s]*)?)\\b");
        
        // Age Secret Key
        addPattern("Age Secret Key", 
            "AGE-SECRET-KEY-1[\\dA-Z]{58}");

        addPattern("Algolia ID", 
            buildPrefixRegex(new String[]{"algolia", "docsearch", "appId"}) + "\\b([A-Z0-9]{10})\\b");
        
        addPattern("Algolia Key", 
            buildPrefixRegex(new String[]{"algolia", "docsearch", "apiKey"}) + "\\b([a-zA-Z0-9]{32})\\b");
        
        addPattern("Azure Storage Account Key", 
            "(?i)(?:account)?key\\s*[:=]\\s*[\"']?([\\d+/=A-Za-z]{88})[\"']?(?:[^\\w]|$)");
        
        addPattern("Azure AD Client Secret", 
            "\\b([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^\\w]|$)");
        
        addPattern("AWS Access Key", 
            "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,20})\\b");

        // Bcrypt Hash pattern
        addPattern("Bcrypt Hash", 
            "\\b\\$2[abxy]\\$\\d{2}\\$[./A-Za-z0-9]{53}\\b");
        
        addPattern("Fastly API Key", 
            "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[^\\w]|$)");
        
        addPattern("GitHub Personal Access Token", 
            "(?:gh[oprsu]|github_pat)_[\\dA-Za-z_]{36}");
        
        addPattern("GitLab Token", 
            "glpat-[\\dA-Za-z_=-]{20,22}");
        
        addPattern("Cloudflare API Token", 
            buildPrefixRegex(new String[]{"cloudflare"}) + "\\b([A-Za-z0-9_-]{40})\\b");
        
        addPattern("Cloudflare Global API Key", 
            buildPrefixRegex(new String[]{"cloudflare"}) + "\\b([A-Za-z0-9_-]{37})\\b");

        addPattern("Cloudflare Origin CA Key", 
            "\\b(v1\\.0-[A-Za-z0-9-]{171})\\b");
        
        addPattern("DigitalOcean Personal Access Token", 
        "\\b((?:dop|doo|dor)_v1_[a-f0-9]{64})\\b");
        
        addPattern("Google Cloud Platform (GCP) API Key", 
        "\\b(AIza[\\w-]{35})\\b");

        addPattern("Heroku API Key v2", 
            "\\b(HRKU-AA[0-9a-zA-Z_-]{58})\\b");

        // Disabled for now.. too many "findings"
        // addPattern("JWT/JWE Token", 
        //     "\\beyJ[\\dA-Za-z=_-]+(?:\\.[\\dA-Za-z=_-]{3,}){1,4}");
        
        addPattern("Mailgun Signing Key", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})\\b");
        
        addPattern("Mailgun Private API Token", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})\\b");
        
        addPattern("OpenAI API Key", 
            "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\\b");
        
        addPattern("NPM Token (modern)", 
            "npm_[\\dA-Za-z]{36}");
        
        addPattern("NPM Token (legacy)", 
            "//.+/:_authToken=[\\dA-Za-z_-]+");

        // Postman API Token
        addPattern("Postman API Token", 
            "\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})\\b");

        // reCAPTCHA Secret Key
        addPattern("Google reCAPTCHA Key", 
            "\\b6[LM][A-Za-z0-9_-]{38}\\b");
        
        addPattern("Slack Token", 
            "xox[aboprs]-(?:\\d+-)+[\\da-z]+");
        
        // Slack Tokens
        addPattern("Slack App Token", 
            "(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+");
            
        addPattern("Slack Bot Token", 
            "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*");
            
        addPattern("Slack Legacy Bot Token", 
            "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}");
            
        addPattern("Slack User Token", 
            "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}");
            
        addPattern("Slack Legacy Token", 
            "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+");
        
        addPattern("Slack Config Access Token", 
            "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}");
        
        addPattern("Slack Config Refresh Token", 
            "(?i)xoxe-\\d-[A-Z0-9]{146}");
        
        addPattern("Slack Legacy Workspace Token", 
            "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}");
        
        addPattern("Slack Webhook URL", 
            "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}");
            
        // Microsoft Teams Webhook
        addPattern("Microsoft Teams Webhook", 
            "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}");
        
        addPattern("SendGrid API Key", 
            "SG\\.[\\dA-Za-z_-]{22}\\.[\\dA-Za-z_-]{43}");
        
        addPattern("Stripe API Key", 
            "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})\\b");
        
        addPattern("Square Access Token", 
            "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})\\b");
        
        addPattern("Squarespace Access Token", 
            "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b");
        
        addPattern("Telegram Bot API Token", 
            buildPrefixRegex(new String[]{"telegram", "tgram://"}) + "\\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\\b");
        
        // Shopify Access Tokens
        addPattern("Shopify Access Token", 
            "shpat_[a-fA-F0-9]{32}");
            
        addPattern("Shopify Custom Access Token", 
            "shpca_[a-fA-F0-9]{32}");
            
        addPattern("Shopify Private App Access Token", 
            "shppa_[a-fA-F0-9]{32}");
            
        addPattern("Shopify Shared Secret", 
            "shpss_[a-fA-F0-9]{32}");
        
        addPattern("Twilio API Key", 
            "\\b(?:AC|SK)[0-9a-fA-F]{32}\\b");
        
        addPattern("Mailchimp API Key", 
            "[0-9a-f]{32}-us[0-9]{1,2}");
        
        addPattern("Intra42 Secret", 
            "s-s4t2(?:af|ud)-[\\da-f]{64}");
        
        addPattern("Zendesk Secret Key", 
            "(?i)[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})\\b");
        
        addPattern("Generic Private Key", 
            "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----");
        
        // Generic Secret pattern (original)
        String randomStringRegex = String.format(RANDOM_STRING_REGEX_TEMPLATE, genericSecretMinLength, genericSecretMaxLength);
        addPattern("Generic Secret", randomStringRegex);
        
        // Generic Secret pattern v2 (TruffleHog-style)
        String randomStringRegex2 = String.format(RANDOM_STRING_REGEX_TEMPLATE2, genericSecretMinLength, genericSecretMaxLength);
        addPattern("Generic Secret v2", randomStringRegex2);
    }
    
    /**
    * Helper method to compile and store a pattern with its metadataa
    */
    private static void addPattern(String name, String regex) {
        try {
            SECRET_PATTERNS.add(new SecretScanner.SecretPattern(
                name, Pattern.compile(regex)));
        } catch (Exception e) {
            String errorMsg = "Failed to compile pattern '" + name + "': " + e.getMessage() + " | Regex: " + regex;
            if (logging != null) {
                logging.logToError(errorMsg);
            } else {
                System.err.println(errorMsg);
            }
        }
    }
    
    /**
    * Get all precompiled secret patterns
    * @return List of SecretPattern objects
    */
    public static List<SecretScanner.SecretPattern> getAllPatterns() {
        return SECRET_PATTERNS;
    }
}