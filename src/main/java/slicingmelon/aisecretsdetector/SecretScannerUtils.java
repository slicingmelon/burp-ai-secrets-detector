package slicingmelon.aisecretsdetector;

import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Utility class for SecretScanner
 */
public class SecretScannerUtils {
    // Random string pattern
    public static final String RANDOM_STRING_REGEX = "(?i:key|token|secret|password)\\w*[\"']?]?\\s*(?:[:=]|:=|=>|<-)\\s*[\\t \"'`]?([\\w+./=~-]{15,80})(?:[\\t\\n \"'`]|$)";
    
    private static final List<SecretScanner.SecretPattern> SECRET_PATTERNS = new ArrayList<>();
    
    // Load and compile patterns during load time
    static {
        addPattern("URL with Credentials", 
            "(?i)\\b[a-zA-Z]+://[^/\\s:@]{3,20}:[^@]{3,100}@[a-zA-Z0-9.-]+\\b", false);
        
        addPattern("Age Secret Key", 
            "AGE-SECRET-KEY-1[\\dA-Z]{58}", false);
        
        addPattern("Azure Storage Account Key", 
            "AccountKey=[\\d+/=A-Za-z]{88}", false);
        
        addPattern("Azure AD Client Secret", 
            "(?:^|[\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'\"\\x60\\s<),])", false);
        
        addPattern("AWS Access Key", 
            "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16,20})\\b", false);
        
        addPattern("Fastly API Key", 
            "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("GitHub Personal Access Token", 
            "(?:gh[oprsu]|github_pat)_[\\dA-Za-z_]{36}", false);
        
        addPattern("GitLab Token", 
            "glpat-[\\dA-Za-z_=-]{20,22}", false);
        
        addPattern("Cloudflare API Key", 
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("Cloudflare Global API Key", 
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("GCP API Key", 
            "AIzaSy[\\dA-Za-z_-]{33}", false);
        
        addPattern("JWT/JWE Token", 
            "\\beyJ[\\dA-Za-z=_-]+(?:\\.[\\dA-Za-z=_-]{3,}){1,4}", false);
        
        addPattern("Mailgun Signing Key", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("Mailgun Private API Token", 
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("OpenAI API Key", 
            "\\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("NPM Token (modern)", 
            "npm_[\\dA-Za-z]{36}", false);
        
        addPattern("NPM Token (legacy)", 
            "//.+/:_authToken=[\\dA-Za-z_-]+", false);
        
        addPattern("Slack Token", 
            "xox[aboprs]-(?:\\d+-)+[\\da-z]+", false);
        
        addPattern("Slack Config Access Token", 
            "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}", false);
        
        addPattern("Slack Legacy Workspace Token", 
            "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}", false);
        
        addPattern("Slack Webhook URL", 
            "(?:https?://)?hooks.slack.com/(?:services|workflows)/[A-Za-z0-9+/]{43,46}", false);
        
        addPattern("SendGrid API Key", 
            "SG\\.[\\dA-Za-z_-]{22}\\.[\\dA-Za-z_-]{43}", false);
        
        addPattern("Stripe API Key", 
            "[rs]k_live_[\\dA-Za-z]{24,247}", false);
        
        addPattern("Square Access Token", 
            "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("Squarespace Access Token", 
            "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)", false);
        
        addPattern("Twilio API Key", 
            "(?:AC|SK)[\\da-z]{32}", false);
        
        addPattern("Mailchimp API Key", 
            "[\\da-f]{32}-us\\d{1,2}", false);
        
        addPattern("Intra42 Secret", 
            "s-s4t2(?:af|ud)-[\\da-f]{64}", false);
        
        addPattern("Private Key", 
            "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----", false);
        
        // Generic Secret pattern
        addPattern("Generic Secret", RANDOM_STRING_REGEX, true);
    }
    
    /**
     * Helper method to compile and store a pattern with its metadataa
     */
    private static void addPattern(String name, String regex, boolean requiresRandomCheck) {
        SECRET_PATTERNS.add(new SecretScanner.SecretPattern(
            name, Pattern.compile(regex), requiresRandomCheck));
    }
    
    /**
     * Get all precompiled secret patterns
     * @return List of SecretPattern objects
     */
    public static List<SecretScanner.SecretPattern> getAllPatterns() {
        return SECRET_PATTERNS;
    }
}