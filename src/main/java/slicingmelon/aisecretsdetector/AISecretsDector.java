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
import burp.api.montoya.core.ToolType;

import javax.swing.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.net.URI;
import java.net.URISyntaxException;


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
            shutdownWorkers();
        });
        
        api.logging().logToOutput("AI Secrets Detector extension loaded successfully");
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
                api.logging().logToOutput("HTTP Handler: Secrets found in response from: " + url);
                
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
                        
                        // Track what types of secrets we found
                        if (!secretTypeMap.containsKey(secretType)) {
                            secretTypeMap.put(secretType, new HashSet<>());
                        }
                        secretTypeMap.get(secretType).add(secretValue);
                        
                        api.logging().logToOutput("HTTP Handler: Found " + secretType + ": " + secretValue);
                    }
                }
                
                Set<String> existingSecrets = extractExistingSecretsForUrl(url);
                api.logging().logToOutput("HTTP Handler: Found " + existingSecrets.size() + " existing secrets for URL: " + url);
                
                // Check if we have new secrets for this URL
                boolean hasNewSecrets = false;
                for (String newSecret : newSecrets) {
                    if (!existingSecrets.contains(newSecret)) {
                        hasNewSecrets = true;
                        api.logging().logToOutput("HTTP Handler: Found new secret: " + newSecret);
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
                    api.logging().logToOutput("HTTP Handler: Adding NEW audit issue for URL: " + requestResponse.request().url());
                    api.siteMap().add(auditIssue);
                } else {
                    api.logging().logToOutput("HTTP Handler: No new secrets found for URL: " + url + ", skipping issue creation");
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
            // fix bug .. extract the base URL without query parameters using URI parser
            String baseUrl = url;
            try {
                URI uri = new URI(url);
   
                baseUrl = new URI(uri.getScheme(), 
                                  uri.getUserInfo(), 
                                  uri.getHost(), 
                                  uri.getPort(),
                                  uri.getPath(), 
                                  null, // No query
                                  null) // No fragment
                         .toString();
                
                api.logging().logToOutput("Normalized URL from " + url + " to " + baseUrl);
            } catch (URISyntaxException e) {
                // If URI parsing fails, fall back to string splitting
                api.logging().logToOutput("Failed to parse URL with URI parser, falling back to string splitting");
                baseUrl = url.contains("?") ? url.split("\\?")[0] : url;
            }
            
            SiteMapFilter urlFilter = SiteMapFilter.prefixFilter(baseUrl);
            
            List<AuditIssue> filteredIssues = api.siteMap().issues(urlFilter);
            
            api.logging().logToOutput("Found " + filteredIssues.size() + " filtered issues for base URL: " + baseUrl);
            
            // Process only our "Exposed Secrets Detected" issues
            for (AuditIssue issue : filteredIssues) {
                if (issue.name().equals("Exposed Secrets Detected")) {
                    if (issue.baseUrl().equals(baseUrl)) {
                        api.logging().logToOutput("Processing existing secret issue from: " + issue.baseUrl());
                        
                        // Process evidence efficiently
                        for (HttpRequestResponse evidence : issue.requestResponses()) {
                            List<Marker> markers = evidence.responseMarkers();
                            
                            if (markers != null && !markers.isEmpty()) {
                                api.logging().logToOutput("Processing " + markers.size() + " markers from evidence");
                                
                                Set<String> secretsFromMarkers = extractSecretsFromMarkers(evidence);
                                existingSecrets.addAll(secretsFromMarkers);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting existing secrets: " + e.getMessage());
            e.printStackTrace();
        }
        
        return existingSecrets;
    }
    
    /*
    * Extract actual secrets from response markers by removing the padding
    */
    private Set<String> extractSecretsFromMarkers(HttpRequestResponse requestResponse) {
        Set<String> extractedSecrets = new HashSet<>();
        
        if (requestResponse == null || requestResponse.response() == null) {
            api.logging().logToOutput("No response to extract markers from");
            return extractedSecrets;
        }
        
        String responseBody = requestResponse.response().bodyToString();
        int bodyOffset = requestResponse.response().bodyOffset();
        List<Marker> markers = requestResponse.responseMarkers();
        
        if (markers == null || markers.isEmpty()) {
            api.logging().logToOutput("No markers found in response");
            return extractedSecrets;
        }
        
        for (Marker marker : markers) {
            try {
                int startPos = marker.range().startIndexInclusive();
                int endPos = marker.range().endIndexExclusive();
                
                // Adjust marker positions to account for the padding (20 chars on each side)
                int adjustedStartPos = startPos + 20;
                int adjustedEndPos = endPos - 20;
                
                // If adjusted positions are invalid, log and continue without extraction
                if (adjustedStartPos >= adjustedEndPos || 
                    adjustedStartPos < bodyOffset || 
                    adjustedEndPos > bodyOffset + responseBody.length()) {
                    
                    api.logging().logToOutput("Invalid marker adjustment, cannot extract secret properly");
                    continue;
                }
                
                // Extract the actual secret without padding
                String secret = requestResponse.response().toString().substring(
                    adjustedStartPos, adjustedEndPos);
                
                if (secret != null && !secret.isEmpty()) {
                    extractedSecrets.add(secret);
                    api.logging().logToOutput("Extracted secret from marker: " + secret);
                }
            } catch (Exception e) {
                api.logging().logToError("Error extracting secret from marker: " + e.getMessage());
            }
        }
        
        return extractedSecrets;
    }
}