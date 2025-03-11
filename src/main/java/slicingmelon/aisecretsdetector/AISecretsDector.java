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
                // Add more debug logging here
                api.logging().logToOutput("Consolidation triggered for path: " + existingPath);
                
                // Get evidence request/responses from issues
                List<HttpRequestResponse> existingEvidence = existingIssue.requestResponses();
                List<HttpRequestResponse> newEvidence = newIssue.requestResponses();
                
                // Add debug logging for the evidence
                api.logging().logToOutput("Existing evidence count: " + existingEvidence.size());
                api.logging().logToOutput("New evidence count: " + newEvidence.size());
                
                // Extract notes from evidence
                String existingNotes = "";
                String newNotes = "";
                
                if (!existingEvidence.isEmpty() && existingEvidence.get(0).annotations() != null) {
                    existingNotes = existingEvidence.get(0).annotations().notes();
                    api.logging().logToOutput("Existing notes: " + existingNotes);
                } else {
                    api.logging().logToOutput("No existing notes found");
                }
                
                if (!newEvidence.isEmpty() && newEvidence.get(0).annotations() != null) {
                    newNotes = newEvidence.get(0).annotations().notes();
                    api.logging().logToOutput("New notes: " + newNotes);
                } else {
                    api.logging().logToOutput("No new notes found");
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
            e.printStackTrace();
        }
        
        // Different endpoints or error occurred
        return ConsolidationAction.KEEP_BOTH;
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
    

    private String extractPathFromUrl(String urlString) {
        try {
            // Add extra handling for just path
            java.net.URI uri = new java.net.URI(urlString);
            String path = uri.getPath();
            
            // Default to "/" if path is empty
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            
            api.logging().logToOutput("Extracted path for consolidation: " + path + " from " + urlString);
            return path;
            
        } catch (Exception e) {
            api.logging().logToError("Error extracting path from URL: " + e.getMessage());
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