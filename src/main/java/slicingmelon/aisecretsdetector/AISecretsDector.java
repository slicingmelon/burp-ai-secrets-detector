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
import java.net.URL;
import java.util.Set;

public class AISecretsDector implements BurpExtension, ScanCheck {
    
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
        
        // Register HTTP handler
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
                
                // Submit the response directly to reduce memory allocations
                executorService.submit(() -> scanResponseForSecrets(responseReceived));
                
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
        
        // Register this class as a ScanCheck for issue consolidation
        api.scanner().registerScanCheck(this);
        
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
    
    // Required ScanCheck methods
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        // Not used but required - return empty result
        return AuditResult.auditResult(new ArrayList<>());
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // Not used but required - return empty result
        return AuditResult.auditResult(new ArrayList<>());
    }
    
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        // Only handle our own issues
        if (!existingIssue.name().equals("Exposed Secrets Detected") || !newIssue.name().equals("Exposed Secrets Detected")) {
            return ConsolidationAction.KEEP_BOTH; // Not our issues, let Burp handle them
        }
        
        try {
            // Get base URLs from issues
            String existingPath = extractPathFromUrl(existingIssue.baseUrl());
            String newPath = extractPathFromUrl(newIssue.baseUrl());
            
            // Check if they're the same endpoint
            if (existingPath.equals(newPath)) {
                // Get evidence request/responses from issues
                List<HttpRequestResponse> existingEvidence = existingIssue.requestResponses();
                List<HttpRequestResponse> newEvidence = newIssue.requestResponses();
                
                // Extract notes from evidence
                String existingNotes = "";
                String newNotes = "";
                
                if (!existingEvidence.isEmpty() && existingEvidence.get(0).annotations() != null) {
                    existingNotes = existingEvidence.get(0).annotations().notes();
                }
                
                if (!newEvidence.isEmpty() && newEvidence.get(0).annotations() != null) {
                    newNotes = newEvidence.get(0).annotations().notes();
                }
                
                // Compare notes to check for new secrets
                if (notesContainNewSecrets(existingNotes, newNotes)) {
                    api.logging().logToOutput("Found new secrets for the same endpoint: " + newPath);
                    return ConsolidationAction.KEEP_BOTH; // Found new secrets
                } else {
                    api.logging().logToOutput("No new secrets for the same endpoint: " + newPath);
                    return ConsolidationAction.KEEP_EXISTING; // No new secrets
                }
            }
        } catch (Exception e) {
            api.logging().logToError("Error during issue consolidation: " + e.getMessage());
        }
        
        // Different endpoints or error occurred
        return ConsolidationAction.KEEP_BOTH;
    }
    
    private boolean notesContainNewSecrets(String existingNotes, String newNotes) {
        if (existingNotes == null || existingNotes.isEmpty()) {
            return true; // No existing notes, so new notes contain new secrets
        }
        
        if (newNotes == null || newNotes.isEmpty()) {
            return false; // No new notes, so no new secrets
        }
        
        // Extract secrets from notes
        Set<String> existingSecrets = extractSecretsFromNotes(existingNotes);
        Set<String> newSecrets = extractSecretsFromNotes(newNotes);
        
        // Check if any new secrets are not in existing secrets
        for (String newSecret : newSecrets) {
            if (!existingSecrets.contains(newSecret)) {
                return true; // Found a new secret
            }
        }
        
        return false; // No new secrets
    }
    
    private Set<String> extractSecretsFromNotes(String notes) {
        Set<String> secrets = new HashSet<>();
        
        // Parse notes assuming format:
        // Detected secrets:
        // - <type>: <value>
        // - <type>: <value>
        
        String[] lines = notes.split("\n");
        for (String line : lines) {
            if (line.startsWith("- ")) {
                // Extract everything after the colon as the secret value
                int colonPos = line.indexOf(": ");
                if (colonPos > 0 && colonPos + 2 < line.length()) {
                    String secretValue = line.substring(colonPos + 2).trim();
                    secrets.add(secretValue);
                }
            }
        }
        
        return secrets;
    }

    private String extractPathFromUrl(String urlString) {
        try {
            java.net.URI uri = new java.net.URI(urlString);
            return uri.getPath();
        } catch (Exception e) {
            // If URI parsing fails, just use the whole string for comparison
            return urlString;
        }
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
                
                // Build notes with detected secrets for consolidation
                StringBuilder secretNotes = new StringBuilder("Detected secrets:\n");
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    // Create a marker for this secret using exact positions
                    responseMarkers.add(Marker.marker(secret.getStartIndex(), secret.getEndIndex()));
                    
                    // Extract the actual secret value for notes
                    String secretValue = "";
                    try {
                        secretValue = tempResponse.bodyToString().substring(
                            secret.getStartIndex(), 
                            secret.getEndIndex()
                        );
                    } catch (Exception e) {
                        secretValue = "[extraction failed]";
                    }
                    
                    // Add to notes
                    secretNotes.append(String.format(
                        "- %s: %s\n", 
                        secret.getType(),
                        secretValue
                    ));
                    
                    api.logging().logToOutput(String.format(
                        "Secret found: %s at position %d-%d", 
                        secret.getType(), 
                        secret.getStartIndex(), 
                        secret.getEndIndex()
                    ));
                }
                
                // Create HttpRequestResponse only when we need it for markers and issue reporting
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
                
                // Add the issue to Burp's issues list
                api.siteMap().add(auditIssue);
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
            e.printStackTrace();
        }
    }
}