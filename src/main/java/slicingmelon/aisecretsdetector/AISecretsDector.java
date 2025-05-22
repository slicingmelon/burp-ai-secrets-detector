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
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.net.URI;
import java.net.URISyntaxException;
import burp.api.montoya.core.ByteArray;

public class AISecretsDector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private Config config;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        config = new Config(api, this::updateWorkers);
        
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
                boolean isFromEnabledTool = false;
                for (ToolType tool : config.getConfigSettings().getEnabledTools()) {
                    if (responseReceived.toolSource().isFromTool(tool)) {
                        isFromEnabledTool = true;
                        break;
                    }
                }
                
                if (!isFromEnabledTool) {
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
                
                // Create markers to highlight where the secrets are in the response
                List<Marker> responseMarkers = new ArrayList<>();
                Set<String> newSecrets = new HashSet<>();
                Map<String, Set<String>> secretTypeMap = new HashMap<>();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    responseMarkers.add(Marker.marker(secret.getStartIndex(), secret.getEndIndex()));
                    
                    String secretValue = secret.getValue(); 
                    String secretType = secret.getType();
                    
                    if (secretValue != null && !secretValue.isEmpty()) {
                        newSecrets.add(secretValue);
                        
                        if (!secretTypeMap.containsKey(secretType)) {
                            secretTypeMap.put(secretType, new HashSet<>());
                        }
                        secretTypeMap.get(secretType).add(secretValue);
                        
                        logMsg("HTTP Handler: Found " + secretType + ": " + secretValue);
                    }
                }
                
                // Check for duplicates using the threshold approach
                Map<String, Integer> secretCounts = countExistingSecrets(baseUrl, newSecrets);
                int duplicateThreshold = config.getConfigSettings().getDuplicateThreshold();
                
                // Filter out secrets that appear too frequently
                Set<String> secretsToReport = new HashSet<>();
                Map<String, Set<String>> secretsToReportByType = new HashMap<>();
                
                for (String secret : newSecrets) {
                    int existingCount = secretCounts.getOrDefault(secret, 0);
                    if (existingCount < duplicateThreshold) {
                        secretsToReport.add(secret);
                        
                        // Find which type this secret belongs to
                        for (Map.Entry<String, Set<String>> entry : secretTypeMap.entrySet()) {
                            if (entry.getValue().contains(secret)) {
                                secretsToReportByType.computeIfAbsent(entry.getKey(), k -> new HashSet<>()).add(secret);
                            }
                        }
                        
                        logMsg("HTTP Handler: Will report secret: " + secret + " (seen " + existingCount + " times, threshold: " + duplicateThreshold + ")");
                    } else {
                        logMsg("HTTP Handler: Skipping secret due to threshold: " + secret + " (seen " + existingCount + " times, threshold: " + duplicateThreshold + ")");
                    }
                }
                
                if (!secretsToReport.isEmpty()) {
                    // Create back the HttpRequestResponse object for markers and issue reporting
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(),
                        tempResponse
                    );
                    
                    HttpRequestResponse markedRequestResponse = requestResponse
                        .withResponseMarkers(responseMarkers);
                    
                    // Build enhanced issue template with table
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
            logMsg("Failed to parse URL for base URL extraction: " + e.getMessage());
            // Fallback to simple extraction
            if (url.contains("://")) {
                String[] parts = url.split("://", 2);
                if (parts.length == 2) {
                    String remaining = parts[1];
                    String hostPart = remaining.split("/")[0];
                    return parts[0] + "://" + hostPart;
                }
            }
            return url;
        }
    }

    /**
    * Count how many times each secret appears in existing issues for the base URL
    */
    private Map<String, Integer> countExistingSecrets(String baseUrl, Set<String> secretsToCheck) {
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
            
            // Extract all secrets from existing issues
            Set<String> allExistingSecrets = new HashSet<>();
            for (AuditIssue issue : existingIssues) {
                for (HttpRequestResponse evidence : issue.requestResponses()) {
                    Set<String> secretsFromMarkers = extractSecretsFromMarkers(evidence);
                    allExistingSecrets.addAll(secretsFromMarkers);
                }
            }
            
            // Count occurrences of each secret we're checking
            for (String secretToCheck : secretsToCheck) {
                int count = 0;
                for (String existingSecret : allExistingSecrets) {
                    if (existingSecret.equals(secretToCheck)) {
                        count++;
                    }
                }
                secretCounts.put(secretToCheck, count);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error counting existing secrets: " + e.getMessage());
            e.printStackTrace();
        }
        
        return secretCounts;
    }

    /**
    * Build enhanced issue detail with table format
    */
    private String buildEnhancedIssueDetail(Map<String, Set<String>> secretsByType, int totalSecrets) {
        StringBuilder detail = new StringBuilder();
        
        detail.append(String.format("<p>%d secrets were detected in the response:</p>", totalSecrets));
        
        // Create table with secret details
        detail.append("<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\" style=\"border-collapse: collapse;\">");
        detail.append("<tr style=\"background-color: #f0f0f0;\"><th>Secret Type</th><th>Plaintext Secret</th></tr>");
        
        // Add each secret as a table row
        for (Map.Entry<String, Set<String>> entry : secretsByType.entrySet()) {
            String secretType = entry.getKey();
            for (String secret : entry.getValue()) {
                detail.append("<tr>");
                detail.append(String.format("<td>%s</td>", secretType));
                detail.append(String.format("<td style=\"font-family: monospace; word-break: break-all;\">%s</td>", secret));
                detail.append("</tr>");
            }
        }
        
        detail.append("</table>");
        
        // Add summary section
        detail.append("<p><b>Summary:</b></p>");
        detail.append("<ul>");
        for (Map.Entry<String, Set<String>> entry : secretsByType.entrySet()) {
            detail.append(String.format("<li>%s: %d total found</li>", 
                    entry.getKey(), entry.getValue().size()));
        }
        detail.append("</ul>");
        
        detail.append("<p>Click the highlights in the response to view the actual secrets.</p>");
        
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
        
        int bodyOffset = requestResponse.response().bodyOffset();
        List<Marker> markers = requestResponse.responseMarkers();
        
        if (markers == null || markers.isEmpty()) {
            logMsg("No markers found in response");
            return extractedSecrets;
        }
        
        // Get only the body as ByteArray
        ByteArray bodyBytes = requestResponse.response().body();
        
        for (Marker marker : markers) {
            try {
                int startPos = marker.range().startIndexInclusive();
                int endPos = marker.range().endIndexExclusive();
                
                // Adjust marker positions to account for the padding and convert to body-relative positions
                // int adjustedStartPos = Math.max(0, (startPos + 20) - bodyOffset);
                // int adjustedEndPos = Math.min(bodyBytes.length(), (endPos - 20) - bodyOffset);

                // Convert to body-relative positions without padding adjustments
                int adjustedStartPos = Math.max(0, startPos - bodyOffset);
                int adjustedEndPos = Math.min(bodyBytes.length(), endPos - bodyOffset);
                
                if (adjustedStartPos >= adjustedEndPos) {
                    logMsg("Invalid marker adjustment, cannot extract secret properly");
                    continue;
                }
                
                // Extract ONLY the bytes needed using subArray
                ByteArray secretBytes = bodyBytes.subArray(adjustedStartPos, adjustedEndPos);
                String secret = secretBytes.toString();
                
                if (secret != null && !secret.isEmpty()) {
                    extractedSecrets.add(secret);
                    logMsg("Extracted secret from marker: " + secret);
                }
            } catch (Exception e) {
                logMsg("Error extracting secret from marker: " + e.getMessage());
            }
        }
        
        return extractedSecrets;
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
}