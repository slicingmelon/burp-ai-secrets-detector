package slicingmelon.aisecretsdetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
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

public class AISecretsDector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private ConfigSettings configSettings;
    
    // Simple config class to avoid creating extra files
    private static class ConfigSettings {
        private int workers;
        private boolean inScopeOnly;
        
        public ConfigSettings(int workers, boolean inScopeOnly) {
            this.workers = workers;
            this.inScopeOnly = inScopeOnly;
        }
        
        public int getWorkers() {
            return workers;
        }
        
        public void setWorkers(int workers) {
            this.workers = workers;
        }
        
        public boolean isInScopeOnly() {
            return inScopeOnly;
        }
        
        public void setInScopeOnly(boolean inScopeOnly) {
            this.inScopeOnly = inScopeOnly;
        }
    }
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        // Initialize configuration and load saved settings
        configSettings = loadConfigSettings(api.persistence().extensionData());
        
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
                if (configSettings.isInScopeOnly() && !responseReceived.initiatingRequest().isInScope()) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                
                // Create HttpRequestResponse for better context and tracking
                HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                    responseReceived.initiatingRequest(),
                    responseReceived
                );
                
                // Submit the response for secret scanning
                executorService.submit(() -> scanResponseForSecrets(requestResponse));
                
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });
        
        // Create and register UI components
        SwingUtilities.invokeLater(() -> {
            JComponent configPanel = createConfigPanel();
            api.userInterface().registerSuiteTab("AI Secrets Detector", configPanel);
        });
        
        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("AI Secrets Detector extension unloading...");
            shutdownWorkers();
        });
        
        api.logging().logToOutput("AI Secrets Detector extension loaded successfully");
    }
    
    private ConfigSettings loadConfigSettings(PersistedObject persistedData) {
        // Fix using null check approach
        Integer workersValue = persistedData.getInteger("workers");
        int workers = (workersValue != null) ? workersValue : 5;
        
        Boolean inScopeOnlyValue = persistedData.getBoolean("in_scope_only");
        boolean inScopeOnly = (inScopeOnlyValue != null) ? inScopeOnlyValue : true;
        
        return new ConfigSettings(workers, inScopeOnly);
    }
    
    private void saveConfigSettings() {
        PersistedObject persistedData = api.persistence().extensionData();
        persistedData.setInteger("workers", configSettings.getWorkers());
        persistedData.setBoolean("in_scope_only", configSettings.isInScopeOnly());
    }
    
    private void initializeWorkers() {
        executorService = Executors.newFixedThreadPool(configSettings.getWorkers());
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
    
    private void scanResponseForSecrets(HttpRequestResponse requestResponse) {
        try {
            // Save response to temp file - this creates a persistent copy
            HttpRequestResponse tempRequestResponse = requestResponse.copyToTempFile();
            
            // Create scanner and scan directly from the response
            SecretScanner scanner = new SecretScanner(api);
            SecretScanner.SecretScanResult result = scanner.scanResponse(tempRequestResponse);
            
            // Process scan results
            if (result.hasSecrets()) {
                api.logging().logToOutput("Secrets found in response from: " + requestResponse.request().url());
                
                // Create markers to highlight where the secrets are in the response
                List<Marker> responseMarkers = new ArrayList<>();
                String responseBody = requestResponse.response().toString();
                
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    // Find the line in the response
                    String[] lines = responseBody.split("\\r?\\n");
                    if (secret.getLineNumber() <= lines.length) {
                        String line = lines[secret.getLineNumber() - 1];
                        int lineStartIndex = responseBody.indexOf(line);
                        
                        if (lineStartIndex >= 0) {
                            int secretStart = lineStartIndex + line.indexOf(secret.getValue());
                            int secretEnd = secretStart + secret.getValue().length();
                            
                            // Create a marker for this secret
                            if (secretStart >= 0 && secretEnd <= responseBody.length()) {
                                responseMarkers.add(Marker.marker(secretStart, secretEnd));
                            }
                        }
                    }
                    
                    api.logging().logToOutput("Secret found: " + secret.getType() + " at line " + secret.getLineNumber());
                }
                
                // Mark the request/response with the found secrets
                HttpRequestResponse markedRequestResponse = requestResponse.withResponseMarkers(responseMarkers);
                
                // Build detailed description of the finding
                StringBuilder detailBuilder = new StringBuilder();
                detailBuilder.append("<p>The following secrets were detected in the response:</p>");
                detailBuilder.append("<ul>");
                for (SecretScanner.Secret secret : result.getDetectedSecrets()) {
                    detailBuilder.append("<li><b>").append(secret.getType()).append("</b>: ");
                    // Mask the actual secret value for security
                    detailBuilder.append("******").append(" (Line ").append(secret.getLineNumber()).append(")</li>");
                }
                detailBuilder.append("</ul>");
                
                // Create remediation advice
                String remediation = "<p>Sensitive information such as API keys, tokens, and other secrets should not be included in HTTP responses. " +
                        "Review the application code to ensure secrets are not leaked to clients.</p>" +
                        "<p>Consider implementing the following:</p>" +
                        "<ul>" +
                        "<li>Remove all hardcoded secrets from source code</li>" +
                        "<li>Store secrets in secure vaults or environment variables</li>" +
                        "<li>Implement proper access controls for sensitive data</li>" +
                        "<li>Sanitize error messages and responses to prevent leaking implementation details</li>" +
                        "</ul>";
                
                // Create an audit issue
                AuditIssue auditIssue = AuditIssue.auditIssue(
                        "Exposed Secret: " + result.getDetectedSecrets().get(0).getType(),
                        detailBuilder.toString(),
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
    
    private JComponent createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create settings panel
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // Workers setting
        JLabel workersLabel = new JLabel("Number of Workers:");
        c.gridx = 0;
        c.gridy = 0;
        settingsPanel.add(workersLabel, c);
        
        SpinnerNumberModel workersModel = new SpinnerNumberModel(
                configSettings.getWorkers(),
                1,
                50,
                1
        );
        JSpinner workersSpinner = new JSpinner(workersModel);
        c.gridx = 1;
        c.gridy = 0;
        settingsPanel.add(workersSpinner, c);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", configSettings.isInScopeOnly());
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 2;
        settingsPanel.add(inScopeCheckbox, c);
        
        // Save button
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> {
            configSettings.setWorkers((Integer) workersSpinner.getValue());
            configSettings.setInScopeOnly(inScopeCheckbox.isSelected());
            
            saveConfigSettings();
            updateWorkers();
            
            api.logging().logToOutput("Configuration saved - Workers: " + configSettings.getWorkers()
                    + ", In-Scope Only: " + configSettings.isInScopeOnly());
        });
        c.gridx = 0;
        c.gridy = 2;
        c.gridwidth = 2;
        settingsPanel.add(saveButton, c);
        
        panel.add(settingsPanel, BorderLayout.NORTH);
        
        // Add results display area (can be enhanced later)
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Detection Results", new JScrollPane(new JTable()));
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
}