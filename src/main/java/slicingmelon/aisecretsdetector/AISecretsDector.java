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
//import java.nio.charset.StandardCharsets;
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
    * Process HTTP response and compare with existing issues
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
                
                Set<String> existingSecrets = extractExistingSecretsForUrl(url);
                logMsg("HTTP Handler: Found " + existingSecrets.size() + " existing secrets for URL: " + url);
                
                // Check if we have new secrets for this URL
                boolean hasNewSecrets = false;
                for (String newSecret : newSecrets) {
                    if (!existingSecrets.contains(newSecret)) {
                        hasNewSecrets = true;
                        logMsg("HTTP Handler: Found new secret: " + newSecret);
                    }
                }
                
                if (hasNewSecrets) {
                    // Create back the HttpRequestResponse object for markers and issue reporting (needed by AuditIssue)
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(),
                        tempResponse  // Use the temp file version of response
                    );
                    
                    HttpRequestResponse markedRequestResponse = requestResponse
                        .withResponseMarkers(responseMarkers);
                    
                    // Build detailed description with secret types
                    StringBuilder detailBuilder = new StringBuilder();
                    detailBuilder.append(String.format("<p>%d secrets were detected in the response:</p><ul>", newSecrets.size()));
                    
                    // Add each type of secret found
                    for (Map.Entry<String, Set<String>> entry : secretTypeMap.entrySet()) {
                        detailBuilder.append(String.format("<li><b>%s</b>: %d found</li>", 
                                entry.getKey(), entry.getValue().size()));
                    }
                    
                    detailBuilder.append("</ul><p>Click the highlights in the response to view the actual secrets.</p>");
                    String detail = detailBuilder.toString();
                    
                    String remediation = "<p>Sensitive information such as API keys, tokens, and other secrets should not be included in HTTP responses. " +
                            "Review the application code to ensure secrets are not leaked to clients.</p>";
                    
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
                    api.siteMap().add(auditIssue);
                } else {
                    logMsg("HTTP Handler: No new secrets found for URL: " + url + ", skipping issue creation");
                }
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error processing HTTP response: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
    * Extract existing secrets for a URL from Burp's site map
    */
    private Set<String> extractExistingSecretsForUrl(String url) {
        Set<String> existingSecrets = new HashSet<>();
    
        try {
            // Extract the base URL without query parameters using URI parser
            String baseUrl = normalizeUrl(url);
            
            SiteMapFilter preciseFilter = new SiteMapFilter() {
                @Override
                public boolean matches(SiteMapNode node) {
                    // Only match our exact URL
                    if (!node.url().equals(baseUrl)) {
                        return false;
                    }
                    
                    // Only match nodes that have "Exposed Secrets Detected" issues
                    for (AuditIssue issue : node.issues()) {
                        if (issue.name().equals("Exposed Secrets Detected")) {
                            return true;
                        }
                    }
                    return false;
                }
            };
            
            // Get only issues that exactly match our filter criteria
            List<AuditIssue> filteredIssues = api.siteMap().issues(preciseFilter);
            
            logMsg("Found " + filteredIssues.size() + " precise filtered issues for URL: " + baseUrl);
            
            for (AuditIssue issue : filteredIssues) {
                for (HttpRequestResponse evidence : issue.requestResponses()) {
                    List<Marker> markers = evidence.responseMarkers();
                    
                    if (markers != null && !markers.isEmpty()) {
                        logMsg("Processing " + markers.size() + " markers from evidence");
                        
                        Set<String> secretsFromMarkers = extractSecretsFromMarkers(evidence);
                        existingSecrets.addAll(secretsFromMarkers);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting existing secrets: " + e.getMessage());
            e.printStackTrace();
        }
        
        return existingSecrets;
    }

    private String normalizeUrl(String url) {
        try {
            URI uri = new URI(url);
            return new URI(uri.getScheme(), 
                          uri.getUserInfo(), 
                          uri.getHost(), 
                          uri.getPort(),
                          uri.getPath(), 
                          null, // No query
                          null) // No fragment
                     .toString();
        } catch (URISyntaxException e) {
            logMsg("Failed to parse URL with URI parser, falling back to string splitting");
            return url.contains("?") ? url.split("\\?")[0] : url;
        }
    }
    
    /*
    * Extract actual secrets from response markers by removing the padding
    */
    // private Set<String> extractSecretsFromMarkers(HttpRequestResponse requestResponse) {
    //     Set<String> extractedSecrets = new HashSet<>();
        
    //     if (requestResponse == null || requestResponse.response() == null) {
    //         logMsg("No response to extract markers from");
    //         return extractedSecrets;
    //     }
        
    //     String responseBody = requestResponse.response().bodyToString();
    //     int bodyOffset = requestResponse.response().bodyOffset();
    //     List<Marker> markers = requestResponse.responseMarkers();
        
    //     if (markers == null || markers.isEmpty()) {
    //         logMsg("No markers found in response");
    //         return extractedSecrets;
    //     }
        
    //     for (Marker marker : markers) {
    //         try {
    //             int startPos = marker.range().startIndexInclusive();
    //             int endPos = marker.range().endIndexExclusive();
                
    //             // Adjust marker positions to account for the padding (20 chars on each side)
    //             int adjustedStartPos = Math.max(bodyOffset, startPos + 20);
    //             int adjustedEndPos = Math.min(bodyOffset + responseBody.length(), endPos - 20);
                
    //             // Only check if we have a valid range (start < end)
    //             if (adjustedStartPos >= adjustedEndPos) {
    //                 logMsg("Invalid marker adjustment, cannot extract secret properly");
    //                 continue;
    //             }
                
    //             // Extract the actual secret without padding, using the already parsed body
    //             // Convert positions from response-relative to body-relative
    //             String secret = responseBody.substring(
    //                 adjustedStartPos - bodyOffset, 
    //                 adjustedEndPos - bodyOffset
    //             );
                
    //             if (secret != null && !secret.isEmpty()) {
    //                 extractedSecrets.add(secret);
    //                 logMsg("Extracted secret from marker: " + secret);
    //             }
    //         } catch (Exception e) {
    //             logMsg("Error extracting secret from marker: " + e.getMessage());
    //         }
    //     }

    //     return extractedSecrets;
    // }

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
                int adjustedStartPos = Math.max(0, (startPos + 20) - bodyOffset);
                int adjustedEndPos = Math.min(bodyBytes.length(), (endPos - 20) - bodyOffset);
                
                if (adjustedStartPos >= adjustedEndPos) {
                    logMsg("Invalid marker adjustment, cannot extract secret properly");
                    continue;
                }
                
                // Extract ONLY the bytes needed using subArray - more efficient!
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