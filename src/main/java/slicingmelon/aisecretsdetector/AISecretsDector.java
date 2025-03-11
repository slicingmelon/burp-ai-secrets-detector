package slicingmelon.aisecretsdetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class AISecretsDector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private Config config;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        // Initialize configuration with a callback for when settings change
        config = new Config(api, this::updateWorkers);
        
        // Initialize worker thread pool
        initializeWorkers();
        
        // Re-enable HTTP handler for real-time detection
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                // We're only interested in responses, not modifying requests
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }
            
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                // Check if we should process this response based on configuration
                if (config.getConfigSettings().isInScopeOnly() && !responseReceived.initiatingRequest().isInScope()) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                // Submit to our worker thread pool for processing
                executorService.submit(() -> processHttpResponse(responseReceived));
                
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
        
        // Create and register UI components
        SwingUtilities.invokeLater(() -> {
            JComponent configPanel = config.createConfigPanel();
            api.userInterface().registerSuiteTab("AI Secrets Detector", configPanel);
        });
        
        // Register unloading handler
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

    /*
    * Process HTTP response and compare with existing issues
    */
    private void processHttpResponse(HttpResponseReceived responseReceived) {
        try {
            // Save response to temp file first (minimize memory usage)
            HttpResponse tempResponse = responseReceived.copyToTempFile();
            
            // Create scanner and scan directly from the temp file response
            SecretScanner scanner = new SecretScanner(api);
            SecretScanner.SecretScanResult result = scanner.scanResponse(tempResponse);
            
            // Process scan results
            if (result.hasSecrets()) {
                String url = responseReceived.initiatingRequest().url().toString();
                api.logging().logToOutput("HTTP Handler: Secrets found in response from: " + url);
                
                // Create markers to highlight where the secrets are in the response
                List<Marker> responseMarkers = new ArrayList<>();
                Set<String> newSecrets = new HashSet<>();
                
                // Build simple notes with just the secrets - one per line
                StringBuilder secretNotes = new StringBuilder();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    // Create a marker for this secret using exact positions for UI highlighting
                    responseMarkers.add(Marker.marker(secret.getStartIndex(), secret.getEndIndex()));
                    
                    // Get the secret value directly from the Secret object
                    String secretValue = secret.getValue(); 
                    
                    // Add to set of secrets found in this response
                    if (secretValue != null && !secretValue.isEmpty()) {
                        newSecrets.add(secretValue);
                        secretNotes.append(secretValue).append("\n");
                        api.logging().logToOutput("HTTP Handler: Found secret: " + secretValue);
                    }
                }
                
                // Find existing issues for this URL
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
                
                // Only create a new issue if we have new secrets
                if (hasNewSecrets) {
                    // Create HttpRequestResponse for markers and issue reporting
                    HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                        responseReceived.initiatingRequest(),
                        tempResponse  // Use the temp file version of response
                    );
                    
                    // Mark the request/response with the found secrets and add notes
                    HttpRequestResponse markedRequestResponse = requestResponse
                        .withResponseMarkers(responseMarkers)
                        .withAnnotations(Annotations.annotations()
                            .withNotes(secretNotes.toString()));
                    
                    // Build generic description
                    String detail = String.format(
                        "<p>%d secrets were detected in the response. Click the highlights to view them.</p>",
                        newSecrets.size()
                    );
                    
                    // Create remediation advice
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

    /*
    * Extract existing secrets for a URL from Burp's site map
    */
    private Set<String> extractExistingSecretsForUrl2(String url) {
        Set<String> existingSecrets = new HashSet<>();
        
        try {
            // Find all audit issues in site map
            for (AuditIssue issue : api.siteMap().issues()) {
                // Only consider our own "Exposed Secrets Detected" issues
                if (issue.name().equals("Exposed Secrets Detected") && issue.baseUrl().equals(url)) {
                    api.logging().logToOutput("Found existing issue for URL: " + url);
                    
                    // Extract secrets from all evidence in this issue
                    for (HttpRequestResponse evidence : issue.requestResponses()) {
                        // Extract secrets from markers
                        Set<String> secretsFromMarkers = extractSecretsFromMarkers(evidence);
                        existingSecrets.addAll(secretsFromMarkers);
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting existing secrets: " + e.getMessage());
        }
        
        return existingSecrets;
    }

    /*
    * Extract existing secrets for a URL from Burp's site map
    */
    private Set<String> extractExistingSecretsForUrl(String url) {
        Set<String> existingSecrets = new HashSet<>();
        
        try {
            // Find all audit issues in site map
            for (AuditIssue issue : api.siteMap().issues()) {
                // Only consider our own "Exposed Secrets Detected" issues
                if (issue.name().equals("Exposed Secrets Detected") && issue.baseUrl().equals(url)) {
                    api.logging().logToOutput("Found existing issue for URL: " + url);
                    
                    // Extract secrets from all evidence in this issue
                    for (HttpRequestResponse evidence : issue.requestResponses()) {
                        // Extract secrets from notes instead of markers
                        if (evidence.annotations() != null && evidence.annotations().notes() != null) {
                            String notes = evidence.annotations().notes();
                            Set<String> secretsFromNotes = extractSecretsFromNotes(notes);
                            existingSecrets.addAll(secretsFromNotes);
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error extracting existing secrets: " + e.getMessage());
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
                // Get marker start and end from the Range object
                int startPos = marker.range().startIndexInclusive();
                int endPos = marker.range().endIndexExclusive();
                
                // Adjust marker positions to account for the padding (we added 20 chars on each side)
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
    
    private boolean notesContainNewSecrets(String existingNotes, String newNotes) {
        if (existingNotes == null || existingNotes.trim().isEmpty()) {
            return newNotes != null && !newNotes.trim().isEmpty();
        }
        
        if (newNotes == null || newNotes.trim().isEmpty()) {
            return false;
        }
        
        // Extract secrets from notes (one per line)
        Set<String> existingSecrets = extractSecretsFromNotes(existingNotes);
        Set<String> newSecrets = extractSecretsFromNotes(newNotes);
        
        // Debug logging to see what's being compared
        api.logging().logToOutput("Consolidation - Existing secrets count: " + existingSecrets.size());
        api.logging().logToOutput("Consolidation - New secrets count: " + newSecrets.size());
        
        // Check if any new secrets are not in existing secrets
        for (String newSecret : newSecrets) {
            if (!existingSecrets.contains(newSecret)) {
                api.logging().logToOutput("Found new secret during consolidation: " + newSecret);
                return true;
            }
        }
        
        return false;
    }
    
    private Set<String> extractSecretsFromNotes(String notes) {
        Set<String> secrets = new HashSet<>();
        
        // Each line is one raw secret
        if (notes != null && !notes.isEmpty()) {
            String[] lines = notes.split("\n");
            for (String line : lines) {
                line = line.trim();
                if (!line.isEmpty()) {
                    secrets.add(line);
                    api.logging().logToOutput("Extracted raw secret from notes: " + line);
                }
            }
        }
        
        return secrets;
    }
    
    private void scanResponseForSecrets(HttpResponseReceived responseReceived) {
        try {
            // Save response to temp file first (minimize memory usage)
            HttpResponse tempResponse = responseReceived.copyToTempFile();
            
            // Create scanner and scan directly from the temp file response
            SecretScanner scanner = new SecretScanner(api);
            SecretScanner.SecretScanResult result = scanner.scanResponse(tempResponse);
            
            // Process scan results
            if (result.hasSecrets()) {
                String url = responseReceived.initiatingRequest().url().toString();
                api.logging().logToOutput("Secrets found in response from: " + url);
                
                // Create markers to highlight where the secrets are in the response
                List<Marker> responseMarkers = new ArrayList<>();
                
                // Build simple notes with just the secrets - one per line
                StringBuilder secretNotes = new StringBuilder();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    // Create a marker for this secret using exact positions for UI highlighting
                    responseMarkers.add(Marker.marker(secret.getStartIndex(), secret.getEndIndex()));
                    
                    // Get the secret value directly from the Secret object
                    String secretValue = secret.getValue(); 
                    
                    // Add to notes - just the raw secret value per line (if not null)
                    if (secretValue != null && !secretValue.isEmpty()) {
                        secretNotes.append(secretValue).append("\n");
                        api.logging().logToOutput("Adding raw secret to notes: " + secretValue);
                    }
                    
                    api.logging().logToOutput(String.format(
                        "Secret found: %s at position %d-%d", 
                        secret.getType(), 
                        secret.getStartIndex(), 
                        secret.getEndIndex()
                    ));
                }
                
                // Create HttpRequestResponse for markers and issue reporting
                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                    responseReceived.initiatingRequest(),
                    tempResponse  // Use the temp file version of response
                );
                
                // Log the notes that will be added
                api.logging().logToOutput("Adding notes to request/response with raw secrets");
                
                // Mark the request/response with the found secrets and add notes
                HttpRequestResponse markedRequestResponse = requestResponse
                    .withResponseMarkers(responseMarkers)
                    .withAnnotations(Annotations.annotations()
                        .withNotes(secretNotes.toString()));
                
                // Debug check if annotations were properly added
                if (markedRequestResponse.annotations() != null && 
                    markedRequestResponse.annotations().notes() != null) {
                    api.logging().logToOutput("Annotations added successfully with " + 
                                             result.getSecretCount() + " raw secrets");
                } else {
                    api.logging().logToOutput("WARNING: Annotations were not added correctly");
                }
                
                // Build generic description
                String detail = String.format(
                    "<p>%d secrets were detected in the response. Click the highlights to view them.</p>",
                    result.getSecretCount()
                );
                
                // Create remediation advice
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
                api.logging().logToOutput("Adding audit issue for URL: " + requestResponse.request().url());
                api.siteMap().add(auditIssue);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
            e.printStackTrace();
        }
    }
}