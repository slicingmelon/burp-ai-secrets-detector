/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.Marker;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.MimeType;

import javax.swing.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.net.URI;
import java.net.URISyntaxException;
import burp.api.montoya.core.ByteArray;

public class AISecretsDetector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private UIConfig config;
    
    // Persistent secret counter map stored as JSON in Burp's extension data
    private Map<String, Map<String, Integer>> secretCounters = new ConcurrentHashMap<>();
    private static final String SECRET_COUNTERS_KEY = "secret_counters";
    
    // Static instance for accessing from Config
    private static AISecretsDetector instance;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        // Set instance for Config access
        instance = this;
        
        config = new UIConfig(api, this::updateWorkers);
        
        // Load persistent secret counters
        loadSecretCounters();
        
        // Initialize worker thread pool
        initializeWorkers();
        
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                // Check if response is from an enabled tool
                if (!isToolEnabled(responseReceived)) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                if (shouldSkipMimeType(responseReceived.mimeType())) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                // Check if in scope only
                if (config.getConfigSettings().isInScopeOnly() && !responseReceived.initiatingRequest().isInScope()) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                // Submit to our worker thread pool for processing
                executorService.submit(() -> processHttpResponse(responseReceived));
                
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
        
        SwingUtilities.invokeLater(() -> {
            JComponent configPanel = config.createConfigPanel();
            api.userInterface().registerSuiteTab("AI Secrets Detector", configPanel);
        });
        
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("AI Secrets Detector extension unloading...");
            logMsg("AI Secrets Detector extension unloading...");
            saveSecretCounters();
            shutdownWorkers();
            config.clearLogs();
        });
        
        api.logging().logToOutput("AI Secrets Detector extension loaded successfully");
        logMsg("AI Secrets Detector extension loaded successfully");
    }
    
    private void initializeWorkers() {
        executorService = Executors.newFixedThreadPool(config.getConfigSettings().getWorkers());
    }
    
    private void shutdownWorkers() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
    
    private void updateWorkers() {
        shutdownWorkers();
        initializeWorkers();
    }

    /**
    * Process HTTP responses
    */
    private void processHttpResponse(HttpResponseReceived responseReceived) {
        try {
            // Save response to temp file first (minimize memory usage)
            HttpResponse tempResponse = responseReceived.copyToTempFile();
            
            SecretScanner scanner = new SecretScanner(api);
            SecretScanner.SecretScanResult result = scanner.scanResponse(tempResponse);
            
            // Process found secrets
            if (result.hasSecrets()) {
                String url = responseReceived.initiatingRequest().url().toString();
                String baseUrl = extractBaseUrl(url);
                logMsg("HTTP Handler: Secrets found in response from: " + url);
                logMsg("HTTP Handler: Base URL: " + baseUrl);
                
                // Create the HttpRequestResponse object first (like official example)
                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                    responseReceived.initiatingRequest(),
                    tempResponse
                );
                
                // Create markers to highlight where the secrets are in the response
                List<Marker> responseMarkers = new ArrayList<>();
                Set<String> newSecrets = new HashSet<>();
                Map<String, Set<String>> secretTypeMap = new HashMap<>();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    String secretValue = secret.getValue(); 
                    String secretType = secret.getType();
                    
                    if (secretValue != null && !secretValue.isEmpty()) {
                        // Use pre-calculated start and end positions from scanner!
                        responseMarkers.add(Marker.marker(secret.getStartIndex(), secret.getEndIndex()));
                        logMsg("HTTP Handler: Found exact position for " + secretType + " at " + secret.getStartIndex() + "-" + secret.getEndIndex());
                        
                        newSecrets.add(secretValue);
                        
                        secretTypeMap.computeIfAbsent(secretType, _ -> new HashSet<>()).add(secretValue);
                        
                        logMsg("HTTP Handler: Found " + secretType + ": " + secretValue);
                    }
                }
                
                // Use our persisted counters combined with existing issues
                Map<String, Integer> existingCounts = getExistingSecretCounts(baseUrl);
                Map<String, Integer> persistedCounts = getPersistedSecretCounts(baseUrl);
                
                // Merge the counts giving precedence to the higher count
                Map<String, Integer> secretCounts = new HashMap<>();
                for (String secret : newSecrets) {
                    int existingCount = existingCounts.getOrDefault(secret, 0);
                    int persistedCount = persistedCounts.getOrDefault(secret, 0);
                    int finalCount = Math.max(existingCount, persistedCount);
                    secretCounts.put(secret, finalCount);
                    
                    logMsg(String.format("Secret count for %s - Existing: %d, Persisted: %d, Final: %d", 
                            secret, existingCount, persistedCount, finalCount));
                }
                
                int duplicateThreshold = config.getConfigSettings().getDuplicateThreshold();
                logMsg("Current duplicate threshold: " + duplicateThreshold);
                
                // Filter out secrets that appear too frequently
                Set<String> secretsToReport = new HashSet<>();
                Map<String, Set<String>> secretsToReportByType = new HashMap<>();
                
                for (String secret : newSecrets) {
                    int count = secretCounts.getOrDefault(secret, 0);
                    if (count < duplicateThreshold) {
                        secretsToReport.add(secret);
                        
                        // Find which type this secret belongs to
                        for (Map.Entry<String, Set<String>> entry : secretTypeMap.entrySet()) {
                            if (entry.getValue().contains(secret)) {
                                secretsToReportByType.computeIfAbsent(entry.getKey(), _ -> new HashSet<>()).add(secret);
                            }
                        }
                        
                        logMsg("HTTP Handler: Will report secret: " + secret + 
                                " (seen " + count + " times, threshold: " + duplicateThreshold + ")");
                        
                        // Increment the counter for this secret
                        incrementSecretCounter(baseUrl, secret);
                    } else {
                        logMsg("HTTP Handler: Skipping secret due to threshold: " + secret + 
                                " (seen " + count + " times, threshold: " + duplicateThreshold + ")");
                    }
                }
                
                if (!secretsToReport.isEmpty()) {
                    // Create back the HttpRequestResponse object for markers and issue reporting
                    HttpRequestResponse markedRequestResponse = requestResponse
                        .withResponseMarkers(responseMarkers);
                    
                    // Build enhanced issue template with simple format and include direct context about positions
                    String detail = buildEnhancedIssueDetail(secretsToReportByType, secretsToReport.size());
                    
                    String remediation = "<p>Sensitive information such as API keys, tokens, and other secrets should not be included in HTTP responses. " +
                            "Review the application code to ensure that sensitive credentials are not hardcoded or exposed in the source code.</p>";
                    
                    // Create an audit issue
                    AuditIssue auditIssue = AuditIssue.auditIssue(
                            "Exposed Secrets Detected",
                            detail,
                            remediation,
                            requestResponse.request().url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.FIRM,
                            "Leaked secrets can lead to unauthorized access and system compromise.",
                            "Properly secure all secrets and sensitive information to prevent exposure.",
                            AuditIssueSeverity.HIGH,
                            markedRequestResponse
                    );
                    
                    // Add the issue to Burp's issues list and log the action
                    logMsg("HTTP Handler: Adding NEW audit issue for URL: " + requestResponse.request().url());
                    logMsg("HTTP Handler: Reporting " + secretsToReport.size() + " new secrets (base URL: " + baseUrl + ")");
                    api.siteMap().add(auditIssue);
                } else {
                    logMsg("HTTP Handler: No new secrets to report for base URL: " + baseUrl + " (all exceeded threshold)");
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error processing HTTP response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
    * Extract base URL (scheme + host + port) for deduplication
    */
    private String extractBaseUrl(String url) {
        try {
            URI uri = new URI(url);
            return new URI(uri.getScheme(), 
                          uri.getUserInfo(), 
                          uri.getHost(), 
                          uri.getPort(),
                          null, // No path
                          null, // No query
                          null) // No fragment
                     .toString();
        } catch (URISyntaxException e) {
            logMsg("Failed to parse URL via Java URI for base URL extraction: " + e.getMessage() + " - URL: " + url);
            
            // Fallback to simple extraction
            try {
                if (url.contains("://")) {
                    String[] parts = url.split("://", 2);
                    if (parts.length == 2) {
                        String remaining = parts[1];
                        String hostPart = remaining.split("/")[0];
                        String fallbackUrl = parts[0] + "://" + hostPart;
                        logMsg("Using fallback base URL extraction: " + fallbackUrl);
                        return fallbackUrl;
                    }
                }
                
                // If fallback also fails
                logMsg("Fallback base URL extraction also failed for URL: " + url);
                return url;
                
            } catch (Exception fallbackException) {
                logMsg("Fallback base URL extraction threw exception: " + fallbackException.getMessage() + " - URL: " + url);
                return url;
            }
        }
    }

    /**
    * Get persisted secret counts for a base URL
    */
    private Map<String, Integer> getPersistedSecretCounts(String baseUrl) {
        return secretCounters.getOrDefault(baseUrl, new HashMap<>());
    }
    
    /**
    * Increment the counter for a specific secret at a base URL
    */
    private void incrementSecretCounter(String baseUrl, String secret) {
        Map<String, Integer> counters = secretCounters.computeIfAbsent(baseUrl, _ -> new ConcurrentHashMap<>());
        counters.compute(secret, (_, v) -> (v == null) ? 1 : v + 1);
        
        // Save counters to persist data
        saveSecretCounters();
    }
    
    /**
    * Load persistent secret counters from extension storage with JSON parsing and base64 decoding
    */
    private void loadSecretCounters() {
        try {
            String countersJson = api.persistence().extensionData().getString(SECRET_COUNTERS_KEY);
            if (countersJson != null && !countersJson.isEmpty()) {
                secretCounters.clear();
                
                // Parse proper JSON format: {"url1":{"secret1":count1,"secret2":count2},"url2":{...}}
                countersJson = countersJson.trim();
                if (!countersJson.startsWith("{") || !countersJson.endsWith("}")) {
                    logMsg("Invalid JSON format in stored counters, resetting");
                    return;
                }
                
                // Remove outer braces
                String content = countersJson.substring(1, countersJson.length() - 1).trim();
                if (content.isEmpty()) {
                    return;
                }
                
                // Parse each base URL entry
                int pos = 0;
                while (pos < content.length()) {
                    // Find base URL
                    if (content.charAt(pos) != '"') break;
                    int urlStart = pos + 1;
                    int urlEnd = findClosingQuote(content, urlStart);
                    if (urlEnd == -1) break;
                    
                    String baseUrl = unescapeJsonString(content.substring(urlStart, urlEnd));
                    pos = urlEnd + 1;
                    
                    // Skip to colon and opening brace
                    while (pos < content.length() && content.charAt(pos) != ':') pos++;
                    pos++; // Skip colon
                    while (pos < content.length() && content.charAt(pos) != '{') pos++;
                    pos++; // Skip opening brace
                    
                    // Find matching closing brace
                    int braceCount = 1;
                    int secretsStart = pos;
                    while (pos < content.length() && braceCount > 0) {
                        if (content.charAt(pos) == '{') braceCount++;
                        else if (content.charAt(pos) == '}') braceCount--;
                        pos++;
                    }
                    
                    String secretsContent = content.substring(secretsStart, pos - 1).trim();
                    Map<String, Integer> secretMap = parseSecretsMap(secretsContent);
                    
                    if (!secretMap.isEmpty()) {
                        secretCounters.put(baseUrl, new ConcurrentHashMap<>(secretMap));
                    }
                    
                    // Skip comma if present
                    while (pos < content.length() && (content.charAt(pos) == ',' || Character.isWhitespace(content.charAt(pos)))) pos++;
                }
            }
            
            logMsg("Loaded " + secretCounters.size() + " base URLs with secret counts from persistent storage (JSON format)");
            
            // Log loaded counters for debugging
            for (Map.Entry<String, Map<String, Integer>> entry : secretCounters.entrySet()) {
                logMsg("Base URL: " + entry.getKey() + " has " + entry.getValue().size() + " secrets tracked");
            }
        } catch (Exception e) {
            logMsg("Error loading secret counters: " + e.getMessage());
            secretCounters.clear();
        }
    }
    
    /**
    * Save persistent secret counters to extension storage using proper JSON format and base64 encoding
    */
    private void saveSecretCounters() {
        try {
            // Use proper JSON format with base64 encoded secret values
            StringBuilder json = new StringBuilder("{");
            
            boolean firstBaseUrl = true;
            for (Map.Entry<String, Map<String, Integer>> baseUrlEntry : secretCounters.entrySet()) {
                if (!firstBaseUrl) {
                    json.append(",");
                }
                firstBaseUrl = false;
                
                // Properly escape base URL for JSON
                json.append("\"").append(escapeJsonString(baseUrlEntry.getKey())).append("\":{");
                
                boolean firstSecret = true;
                for (Map.Entry<String, Integer> secretEntry : baseUrlEntry.getValue().entrySet()) {
                    if (!firstSecret) {
                        json.append(",");
                    }
                    firstSecret = false;
                    
                    // Base64 encode secret value to handle special characters safely
                    String encodedSecret = api.utilities().base64Utils().encodeToString(secretEntry.getKey());
                    json.append("\"").append(encodedSecret).append("\":").append(secretEntry.getValue());
                }
                
                json.append("}");
            }
            
            json.append("}");
            
            api.persistence().extensionData().setString(SECRET_COUNTERS_KEY, json.toString());
            logMsg("Saved secret counters to persistent storage (JSON format with base64 encoding)");
        } catch (Exception e) {
            logMsg("Error saving secret counters: " + e.getMessage());
        }
    }
    
    /**
    * Count secrets in existing issues
    */
    private Map<String, Integer> getExistingSecretCounts(String baseUrl) {
        Map<String, Integer> secretCounts = new HashMap<>();
        
        try {
            SiteMapFilter baseUrlFilter = new SiteMapFilter() {
                @Override
                public boolean matches(SiteMapNode node) {
                    String nodeBaseUrl = extractBaseUrl(node.url());
                    
                    // Match base URLs and only our issue type
                    if (!nodeBaseUrl.equals(baseUrl)) {
                        return false;
                    }
                    
                    for (AuditIssue issue : node.issues()) {
                        if (issue.name().equals("Exposed Secrets Detected")) {
                            return true;
                        }
                    }
                    return false;
                }
            };
            
            List<AuditIssue> existingIssues = api.siteMap().issues(baseUrlFilter);
            logMsg("Found " + existingIssues.size() + " existing issues for base URL: " + baseUrl);
            
            // Process each issue to count secret occurrences - BUT ONLY OUR ISSUE TYPE
            for (AuditIssue issue : existingIssues) {
                // Only process "Exposed Secrets Detected" issues created by this extension
                if (!issue.name().equals("Exposed Secrets Detected")) {
                    continue;
                }
                
                for (HttpRequestResponse evidence : issue.requestResponses()) {
                    Set<String> secretsFromMarkers = extractSecretsFromMarkers(evidence);
                    logMsg("Extracted " + secretsFromMarkers.size() + " secrets from markers in issue: " + issue.name());
                    
                    // Count each found secret
                    for (String secret : secretsFromMarkers) {
                        int count = secretCounts.getOrDefault(secret, 0);
                        secretCounts.put(secret, count + 1);
                        logMsg("Counted existing secret: " + secret + " (count=" + (count + 1) + ")");
                    }
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error counting existing secrets: " + e.getMessage());
            e.printStackTrace();
        }
        
        return secretCounts;
    }

    /**
    * Build enhanced issue detail with simple format and include direct context about positions
    */
    private String buildEnhancedIssueDetail(Map<String, Set<String>> secretsByType, int totalSecrets) {
        StringBuilder detail = new StringBuilder();
        
        detail.append(String.format("<p>%d secrets were detected in the response:</p>", totalSecrets));
        
        // List each secret with its type (simple format since tables don't work well in Burp)
        detail.append("<p><b>Detected Secrets:</b></p>");
        detail.append("<ul>");
        
        for (Map.Entry<String, Set<String>> entry : secretsByType.entrySet()) {
            String secretType = entry.getKey();
            for (String secret : entry.getValue()) {
                // Add a clear indicator of what to look for in the response
                detail.append(String.format("<li><b>%s:</b> <code>%s</code></li>", 
                        secretType, secret));
            }
        }
        
        detail.append("</ul>");
        
        // Add summary section
        detail.append("<p><b>Summary:</b></p>");
        detail.append("<ul>");
        for (Map.Entry<String, Set<String>> entry : secretsByType.entrySet()) {
            detail.append(String.format("<li>%s: %d total found</li>", 
                    entry.getKey(), entry.getValue().size()));
        }
        detail.append("</ul>");
        
        // Add a clear instruction about how to find the secrets
        detail.append("<p>Click on the highlights in the <b>response</b> panel to view the exact secrets. Look for the exact strings shown above.</p>");
        
        return detail.toString();
    }

    /**
    * Extract actual secrets from response markers
    */
    private Set<String> extractSecretsFromMarkers(HttpRequestResponse requestResponse) {
        Set<String> extractedSecrets = new HashSet<>();
    
        if (requestResponse == null || requestResponse.response() == null) {
            logMsg("No response to extract markers from");
            return extractedSecrets;
        }
        
        List<Marker> markers = requestResponse.responseMarkers();
        
        if (markers == null || markers.isEmpty()) {
            logMsg("No markers found in response");
            return extractedSecrets;
        }
        
        // Get full response as ByteArray
        ByteArray responseBytes = requestResponse.response().toByteArray();
        
        for (Marker marker : markers) {
            try {
                int startPos = marker.range().startIndexInclusive();
                int endPos = marker.range().endIndexExclusive();
                
                // Simple bounds checking
                if (startPos >= 0 && endPos <= responseBytes.length() && startPos < endPos) {
                    // Extract bytes directly from the full response
                    ByteArray secretBytes = responseBytes.subArray(startPos, endPos);
                    String secret = secretBytes.toString();
                    
                    if (secret != null && !secret.isEmpty()) {
                        // Only store non-empty secrets
                        extractedSecrets.add(secret);
                        logMsg("Extracted secret from marker: " + secret);
                    }
                } else {
                    logMsg("Invalid marker position: " + startPos + "-" + endPos + 
                          " (response length: " + responseBytes.length() + ")");
                }
            } catch (Exception e) {
                logMsg("Error extracting secret from marker: " + e.getMessage());
            }
        }
        
        return extractedSecrets;
    }
    
    /**
     * Check if the response is from an enabled tool (proxy, scanner, etc)
     * @param responseReceived The HTTP response to check
     * @return true if the response is from an enabled tool, false otherwise
     */
    private boolean isToolEnabled(HttpResponseReceived responseReceived) {
        for (ToolType tool : config.getConfigSettings().getEnabledTools()) {
            if (responseReceived.toolSource().isFromTool(tool)) {
                return true;
            }
        }
        return false;
    }

    // Skip binary content types that are unlikely to contain secrets
    public boolean shouldSkipMimeType(MimeType mimeType) {
        switch (mimeType) {
            case IMAGE_BMP:
            case IMAGE_GIF:
            case IMAGE_JPEG:
            case IMAGE_PNG:
            case IMAGE_SVG_XML:
            case IMAGE_TIFF:
            case IMAGE_UNKNOWN:
            case FONT_WOFF:
            case FONT_WOFF2:
            case SOUND:
            case VIDEO:
            case APPLICATION_FLASH:
            case RTF:
            case APPLICATION_UNKNOWN: // risky but burp does not detect enough useless mime types (e.g font/ttf etc)
            case UNRECOGNIZED: // risky but burp does not detect enough useless mime types (e.g font/ttf etc)
                return true;
            // Process all other MIME types
            default:
                return false;
        }
    }

    private void logPoolStats() {
        if (executorService instanceof ThreadPoolExecutor) {
            ThreadPoolExecutor pool = (ThreadPoolExecutor) executorService;
            logMsg(String.format(
                "Thread pool stats - Active: %d, Completed: %d, Task Count: %d, Queue Size: %d",
                pool.getActiveCount(),
                pool.getCompletedTaskCount(),
                pool.getTaskCount(),
                pool.getQueue().size()
            ));
        }
    }

    // helper function to log messages 
    private void logMsg(String message) {
        // burp's logger
        //api.logging().logToOutput(message);
        
        // Also log to UI if enabled
        if (config != null && config.getConfigSettings().isLoggingEnabled()) {
            config.appendToLog(message);
        }
    }

    /**
     * Get the static instance for use by Config
     */
    public static AISecretsDetector getInstance() {
        return instance;
    }
    
    /**
     * Clear all secret counters
     */
    public void clearSecretCounters() {
        secretCounters.clear();
        saveSecretCounters();
        logMsg("All secret counters cleared");
    }

    /**
     * Escape special characters in strings for JSON format
     */
    private String escapeJsonString(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    private String unescapeJsonString(String input) {
        if (input == null) return "";
        return input.replace("\\n", "\n")
                   .replace("\\r", "\r")
                   .replace("\\t", "\t")
                   .replace("\\\"", "\"")
                   .replace("\\\\", "\\");
    }

    private Map<String, Integer> parseSecretsMap(String secretsContent) {
        Map<String, Integer> secretMap = new HashMap<>();
        if (secretsContent.trim().isEmpty()) {
            return secretMap;
        }
        
        // Parse JSON-style secret entries: "base64secret1":count1,"base64secret2":count2
        int pos = 0;
        while (pos < secretsContent.length()) {
            // Skip whitespace
            while (pos < secretsContent.length() && Character.isWhitespace(secretsContent.charAt(pos))) pos++;
            if (pos >= secretsContent.length()) break;
            
            // Find quoted secret key
            if (secretsContent.charAt(pos) != '"') break;
            int keyStart = pos + 1;
            int keyEnd = findClosingQuote(secretsContent, keyStart);
            if (keyEnd == -1) break;
            
            String encodedSecret = secretsContent.substring(keyStart, keyEnd);
            pos = keyEnd + 1;
            
            // Skip to colon
            while (pos < secretsContent.length() && secretsContent.charAt(pos) != ':') pos++;
            pos++; // Skip colon
            
            // Parse count value
            while (pos < secretsContent.length() && Character.isWhitespace(secretsContent.charAt(pos))) pos++;
            int valueStart = pos;
            while (pos < secretsContent.length() && Character.isDigit(secretsContent.charAt(pos))) pos++;
            
            if (valueStart < pos) {
                try {
                    int count = Integer.parseInt(secretsContent.substring(valueStart, pos));
                    // Base64 decode the secret value using Burp's utilities
                    String decodedSecret = api.utilities().base64Utils().decode(encodedSecret).toString();
                    secretMap.put(decodedSecret, count);
                } catch (Exception e) {
                    logMsg("Error decoding secret: " + e.getMessage());
                }
            }
            
            // Skip comma if present
            while (pos < secretsContent.length() && (secretsContent.charAt(pos) == ',' || Character.isWhitespace(secretsContent.charAt(pos)))) pos++;
        }
        
        return secretMap;
    }

    private int findClosingQuote(String content, int startPos) {
        for (int pos = startPos; pos < content.length(); pos++) {
            if (content.charAt(pos) == '"' && (pos == startPos || content.charAt(pos - 1) != '\\')) {
                return pos;
            }
        }
        return -1;
    }
}