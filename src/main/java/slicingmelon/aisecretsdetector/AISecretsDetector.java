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
import burp.api.montoya.utilities.json.JsonUtils;
import burp.api.montoya.utilities.json.JsonObjectNode;
import burp.api.montoya.utilities.json.JsonNode;
import burp.api.montoya.utilities.json.JsonNumberNode;

import javax.swing.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import burp.api.montoya.core.ByteArray;

public class AISecretsDetector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private Config config;
    private UI ui;
    private SecretScanner secretScanner;
    
    // Persistent secret counter map stored as JSON in Burp's extension data
    private Map<String, Map<String, Integer>> secretCounters = new ConcurrentHashMap<>();
    private static final String SECRET_COUNTERS_KEY = "secret_counters";
    
    // Static instance for accessing from Config
    private static AISecretsDetector instance;
    

    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        // Initialize Logger first
        Logger.initialize(api);
        
        // Set instance for Config access
        instance = this;
        
        try {
            // Initialize config first and ensure it's fully loaded
            config = Config.initialize(api, this::updateWorkers);
            
            // Now create UI and SecretScanner after config is confirmed to be ready
            ui = new UI(api);
            secretScanner = new SecretScanner(api);
            
        } catch (Exception e) {
            // Log the error but continue with minimal functionality
            api.logging().logToError("Error during extension initialization: " + e.getMessage());
            e.printStackTrace();
            
            // Ensure we have minimal working components
            if (config == null) {
                config = Config.getInstance(); // This will create a minimal instance
            }
            if (ui == null) {
                ui = new UI(api);
            }
            if (secretScanner == null) {
                secretScanner = new SecretScanner(api);
            }
        }
        
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
                Logger.logCritical("AISecretsDetector: HTTP response received from " + responseReceived.initiatingRequest().url());
                
                // Check if response is from an enabled tool
                if (!isToolEnabled(responseReceived)) {
                    Logger.logCritical("AISecretsDetector: Response filtered out - not from enabled tool");
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                // Skip binary file extensions that are unlikely to contain secrets
                if (shouldSkipFileExtension(responseReceived.initiatingRequest().fileExtension())) {
                    Logger.logCritical("AISecretsDetector: Response filtered out - file extension: " + responseReceived.initiatingRequest().fileExtension());
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                if (shouldSkipMimeType(responseReceived.mimeType())) {
                    Logger.logCritical("AISecretsDetector: Response filtered out - MIME type: " + responseReceived.mimeType());
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                // Check if in scope only
                if (config.getSettings().isInScopeOnly() && !responseReceived.initiatingRequest().isInScope()) {
                    Logger.logCritical("AISecretsDetector: Response filtered out - not in scope");
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                Logger.logCritical("AISecretsDetector: Response passed all filters, submitting to worker thread");
                
                // Submit to our worker thread pool for processing
                executorService.submit(() -> processHttpResponse(responseReceived));
                
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
        
        SwingUtilities.invokeLater(() -> {
            JComponent configPanel = ui.createConfigPanel();
            api.userInterface().registerSuiteTab("AI Secrets Detector", configPanel);
        });
        
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("AI Secrets Detector extension unloading...");
            saveSecretCounters();
            shutdownWorkers();
            ui.clearLogs();
        });
        
        api.logging().logToOutput("AI Secrets Detector " + VersionUtil.getFormattedVersion() + " extension loaded successfully");
    }
    
    private void initializeWorkers() {
        executorService = Executors.newFixedThreadPool(config.getSettings().getWorkers());
    }
    
    private void shutdownWorkers() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
    
    private void updateWorkers() {
        shutdownWorkers();
        initializeWorkers();
        
        // Also reinitialize scanner to pick up any pattern changes
        if (secretScanner != null) {
            secretScanner = new SecretScanner(api);
            logMsg("SecretScanner reinitialized due to configuration change");
        }
    }

    /**
    * Process HTTP responses
    */
    private void processHttpResponse(HttpResponseReceived responseReceived) {
        Logger.logCritical("AISecretsDetector.processHttpResponse: Processing response from " + responseReceived.initiatingRequest().url());
        
        try {
            // Save response to temp file first (minimize memory usage)
            HttpResponse tempResponse = responseReceived.copyToTempFile();
            
            Logger.logCritical("AISecretsDetector.processHttpResponse: Calling secretScanner.scanResponse");
            SecretScanner.SecretScanResult result = secretScanner.scanResponse(tempResponse);
            
            Logger.logCritical("AISecretsDetector.processHttpResponse: Scanner returned " + result.getSecretCount() + " secrets");
            
            // Process found secrets
            if (result.hasSecrets()) {
                String url = responseReceived.initiatingRequest().url().toString();
                String baseUrl = extractBaseUrl(url);
                Logger.logCritical("AISecretsDetector.processHttpResponse: Secrets found in response from: " + url);
                Logger.logCritical("AISecretsDetector.processHttpResponse: Base URL: " + baseUrl);
                
                // Create the HttpRequestResponse object first (like official example)
                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                    responseReceived.initiatingRequest(),
                    tempResponse
                );
                
                // *** STEP 2: MARKER CREATION ***
                // Create markers to highlight where the secrets are in the response
                // These markers will create the RED highlights visible in Burp's response panel
                List<Marker> responseMarkers = new ArrayList<>();
                Set<String> newSecrets = new HashSet<>();
                Map<String, Set<String>> secretTypeMap = new HashMap<>();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    String secretValue = secret.getValue(); 
                    String secretType = secret.getType();
                    
                    if (secretValue != null && !secretValue.isEmpty()) {
                        // *** POSITION VALIDATION AND CORRECTION ***
                        // Check if the calculated positions actually match the expected secret value
                        int finalStartPos = secret.getStartIndex();
                        int finalEndPos = secret.getEndIndex();
                        
                        if (!validateSecretPosition(tempResponse.toByteArray(), secretValue, finalStartPos, finalEndPos)) {
                            ByteArray actualBytes = tempResponse.toByteArray().subArray(finalStartPos, finalEndPos);
                            String actualFound = actualBytes.toString();
                            Logger.logCritical("POSITION MISMATCH DETECTED:");
                            Logger.logCritical("  Expected secret: '" + secretValue + "'");
                            Logger.logCritical("  Actually found at " + finalStartPos + "-" + finalEndPos + ": '" + actualFound + "'");
                            Logger.logCritical("  Secret type: " + secretType);
                            Logger.logCritical("  Response length: " + tempResponse.toByteArray().length() + " bytes");
                            
                            // *** ATTEMPT POSITION CORRECTION ***
                            int[] correctedPos = findCorrectSecretPosition(tempResponse.toByteArray(), secretValue, finalStartPos, finalEndPos);
                            if (correctedPos[0] != finalStartPos || correctedPos[1] != finalEndPos) {
                                // Verify the correction worked
                                if (validateSecretPosition(tempResponse.toByteArray(), secretValue, correctedPos[0], correctedPos[1])) {
                                    Logger.logCritical("POSITION CORRECTED:");
                                    Logger.logCritical("  Original position: " + finalStartPos + "-" + finalEndPos);
                                    Logger.logCritical("  Corrected position: " + correctedPos[0] + "-" + correctedPos[1]);
                                    Logger.logCritical("  Correction successful for secret: '" + secretValue + "'");
                                    finalStartPos = correctedPos[0];
                                    finalEndPos = correctedPos[1];
                                } else {
                                    Logger.logCritical("POSITION CORRECTION FAILED - using original positions");
                                }
                            } else {
                                Logger.logCritical("POSITION CORRECTION: No alternative position found");
                            }
                        }
                        
                        // *** STEP 2: CREATE INDIVIDUAL MARKER ***
                        // Use corrected positions (or original if no correction needed/possible)
                        responseMarkers.add(Marker.marker(finalStartPos, finalEndPos));
                        Logger.logCritical("AISecretsDetector.processHttpResponse: Found exact position for " + secretType + " at " + finalStartPos + "-" + finalEndPos);
                        
                        newSecrets.add(secretValue);
                        
                        secretTypeMap.computeIfAbsent(secretType, _ -> new HashSet<>()).add(secretValue);
                        
                        Logger.logCritical("AISecretsDetector.processHttpResponse: Found " + secretType + ": " + secretValue);
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
                    
                    Logger.logCritical("AISecretsDetector.processHttpResponse: Secret count for " + secret + " - Existing: " + existingCount + ", Persisted: " + persistedCount + ", Final: " + finalCount);
                }
                
                int duplicateThreshold = config.getSettings().getDuplicateThreshold();
                Logger.logCritical("AISecretsDetector.processHttpResponse: Current duplicate threshold: " + duplicateThreshold);
                
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
                        
                        Logger.logCritical("AISecretsDetector.processHttpResponse: Will report secret: " + secret + " (seen " + count + " times, threshold: " + duplicateThreshold + ")");
                        
                        // Increment the counter for this secret
                        incrementSecretCounter(baseUrl, secret);
                    } else {
                        Logger.logCritical("AISecretsDetector.processHttpResponse: Skipping secret due to threshold: " + secret + " (seen " + count + " times, threshold: " + duplicateThreshold + ")");
                    }
                }
                
                if (!secretsToReport.isEmpty()) {
                    // *** STEP 3: MARKER APPLICATION - CREATE RED RESPONSE HIGHLIGHTS ***
                    // Apply all the markers to the HttpRequestResponse to create the actual RED highlights
                    // that will be visible in Burp's response panel when viewing the audit issue
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
                    Logger.logCritical("AISecretsDetector.processHttpResponse: Adding NEW audit issue for URL: " + requestResponse.request().url());
                    Logger.logCritical("AISecretsDetector.processHttpResponse: Reporting " + secretsToReport.size() + " new secrets (base URL: " + baseUrl + ")");
                    api.siteMap().add(auditIssue);
                } else {
                    Logger.logCritical("AISecretsDetector.processHttpResponse: No new secrets to report for base URL: " + baseUrl + " (all exceeded threshold)");
                }
            } else {
                Logger.logCritical("AISecretsDetector.processHttpResponse: No secrets found in response");
            }
            
        } catch (Exception e) {
            Logger.logCriticalError("AISecretsDetector.processHttpResponse: Error processing HTTP response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
    * Extract base URL (scheme + host + port) for deduplication
    */
    private String extractBaseUrl(String url) {
        // Simple and reliable URL base extraction
        try {
            if (url.contains("://")) {
                String[] parts = url.split("://", 2);
                if (parts.length == 2) {
                    String remaining = parts[1];
                    String hostPart = remaining.split("/")[0];
                    return parts[0] + "://" + hostPart;
                }
            }
            
            // If no protocol, return as-is
            return url;
            
        } catch (Exception e) {
            logMsg("Base URL extraction failed: " + e.getMessage() + " - URL: " + url);
            return url;
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
    * Load persistent secret counters from extension storage using Burp's JsonUtils
    */
    private void loadSecretCounters() {
        try {
            String countersJson = api.persistence().extensionData().getString(SECRET_COUNTERS_KEY);
            if (countersJson != null && !countersJson.isEmpty()) {
                JsonUtils jsonUtils = api.utilities().jsonUtils();
                
                // Validate JSON first
                if (!jsonUtils.isValidJson(countersJson)) {
                    logMsg("Invalid JSON format in stored counters, resetting");
                    return;
                }
                
                secretCounters.clear();
                
                // Parse the JSON using Burp's API
                JsonNode rootNode = JsonNode.jsonNode(countersJson);
                if (rootNode.isObject()) {
                    JsonObjectNode rootObject = rootNode.asObject();
                    
                    // Iterate through each base URL in the root object
                    for (Map.Entry<String, JsonNode> baseUrlEntry : rootObject.asMap().entrySet()) {
                        String baseUrl = baseUrlEntry.getKey();
                        JsonNode secretsNode = baseUrlEntry.getValue();
                        
                        if (secretsNode.isObject()) {
                            JsonObjectNode secretsObject = secretsNode.asObject();
                            Map<String, Integer> secretMap = new HashMap<>();
                            
                            // Iterate through each secret in this base URL
                            for (Map.Entry<String, JsonNode> secretEntry : secretsObject.asMap().entrySet()) {
                                String encodedSecret = secretEntry.getKey();
                                JsonNode countNode = secretEntry.getValue();
                                
                                if (countNode.isNumber()) {
                                    try {
                                        int count = countNode.asNumber().intValue();
                                        // Base64 decode the secret value
                                        String decodedSecret = api.utilities().base64Utils().decode(encodedSecret).toString();
                                        secretMap.put(decodedSecret, count);
                                    } catch (Exception e) {
                                        logMsg("Error decoding secret: " + e.getMessage());
                                    }
                                }
                            }
                            
                            if (!secretMap.isEmpty()) {
                                secretCounters.put(baseUrl, new ConcurrentHashMap<>(secretMap));
                            }
                        }
                    }
                }
            }
            
            logMsg("Loaded " + secretCounters.size() + " base URLs with secret counts using Burp JsonNode API");
            
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
    * Save persistent secret counters to extension storage using Burp's JsonObjectNode
    */
    private void saveSecretCounters() {
        try {
            // Create the main JSON object using Burp's API
            JsonObjectNode mainJson = JsonObjectNode.jsonObjectNode();
            
            // Add each base URL and its secrets
            for (Map.Entry<String, Map<String, Integer>> baseUrlEntry : secretCounters.entrySet()) {
                String baseUrl = baseUrlEntry.getKey();
                
                // Create secrets object for this base URL
                JsonObjectNode secretsJson = JsonObjectNode.jsonObjectNode();
                for (Map.Entry<String, Integer> secretEntry : baseUrlEntry.getValue().entrySet()) {
                    // Base64 encode secret value to handle special characters safely
                    String encodedSecret = api.utilities().base64Utils().encodeToString(secretEntry.getKey());
                    secretsJson.put(encodedSecret, JsonNumberNode.jsonNumberNode(secretEntry.getValue()));
                }
                
                // Add this base URL's secrets to the main JSON
                mainJson.put(baseUrl, secretsJson);
            }
            
            // Convert to JSON string and save
            String jsonString = mainJson.toJsonString();
            api.persistence().extensionData().setString(SECRET_COUNTERS_KEY, jsonString);
            logMsg("Saved secret counters using Burp JsonObjectNode (base64 encoded secrets)");
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
            logMsgError("Error counting existing secrets: " + e.getMessage());
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
        for (ToolType tool : config.getSettings().getEnabledTools()) {
            if (responseReceived.toolSource().isFromTool(tool)) {
                return true;
            }
        }
        return false;
    }

    // Skip binary content types that are unlikely to contain secrets
    // Uses the config's excluded MIME types for O(1) lookup performance
    public boolean shouldSkipMimeType(MimeType mimeType) {
        if (mimeType == null) {
            return false; // Process unknown MIME types
        }
        
        // Convert MimeType enum to string representation for lookup
        String mimeTypeString = mimeType.name();
        
        // Use the config's excluded MIME types
        return config != null && config.getSettings().getExcludedMimeTypes().contains(mimeTypeString);
    }

    /**
     * Skip file extensions that are unlikely to contain secrets (binary files, media, etc.)
     * Uses the config's excluded file extensions for O(1) lookup performance
     * @param fileExtension The file extension to check (can be null or empty)
     * @return true if the file extension should be skipped, false otherwise
     */
    public boolean shouldSkipFileExtension(String fileExtension) {
        if (fileExtension == null || fileExtension.isEmpty()) {
            return false; // Process files without extensions
        }
        
        // Convert to lowercase for case-insensitive comparison
        String ext = fileExtension.toLowerCase();
        
        // Remove leading dot if present (e.g., ".jpg" -> "jpg")
        if (ext.startsWith(".")) {
            ext = ext.substring(1);
        }
        
        // Use the config's excluded file extensions
        return config != null && config.getSettings().getExcludedFileExtensions().contains(ext);
    }

    // helper function to log normal messages - only UI logging
    public void logMsg(String message) {
        // Only log to UI if logging is enabled
        if (config != null && config.getSettings().isLoggingEnabled() && ui != null) {
            ui.appendToLog(message);
        }
    }

    // helper function to log error messages - only UI logging
    public void logMsgError(String message) {
        // Only log to UI if logging is enabled
        if (config != null && config.getSettings().isLoggingEnabled() && ui != null) {
            ui.appendToErrorLog(message);
        }
    }

    /**
     * Get the static instance for use by Config
     */
    public static AISecretsDetector getInstance() {
        return instance;
    }
    
    public Config getConfig() {
        return config;
    }
    
    public UI getUI() {
        return ui;
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
     * Validate that the secret position matches the expected secret value
     * This is for diagnostic purposes to detect UTF-8 encoding position mismatches
     */
    private boolean validateSecretPosition(ByteArray responseBytes, String expectedSecret, int startPos, int endPos) {
        if (startPos < 0 || endPos > responseBytes.length() || startPos >= endPos) {
            return false;
        }
        
        ByteArray actualBytes = responseBytes.subArray(startPos, endPos);
        String actualSecret = actualBytes.toString();
        
        return expectedSecret.equals(actualSecret);
    }
    
    /**
     * Find the correct position of a secret in the response bytes
     * Used to correct position mismatches caused by Burp's character encoding interpretation
     */
    private int[] findCorrectSecretPosition(ByteArray responseBytes, String secretValue, int originalStartPos, int originalEndPos) {
        try {
            // Convert secret to bytes using the same encoding as ByteArray
            ByteArray secretBytes = ByteArray.byteArray(secretValue);
            
            // Search in a reasonable range around the original position
            int searchStart = Math.max(0, originalStartPos - 200);
            int searchEnd = Math.min(responseBytes.length(), originalEndPos + 200);
            
            // First try exact search from the beginning of search range
            int foundPos = responseBytes.indexOf(secretBytes, true, searchStart, searchEnd);
            if (foundPos >= 0) {
                return new int[]{foundPos, foundPos + secretBytes.length()};
            }
            
            // If not found, try a more comprehensive search in the entire response
            foundPos = responseBytes.indexOf(secretBytes, true);
            if (foundPos >= 0) {
                return new int[]{foundPos, foundPos + secretBytes.length()};
            }
            
            // If still not found, return original positions
            return new int[]{originalStartPos, originalEndPos};
            
        } catch (Exception e) {
            logMsg("Error finding correct secret position: " + e.getMessage());
            return new int[]{originalStartPos, originalEndPos};
        }
    }
}