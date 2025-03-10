package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;

import java.io.File;
import java.util.concurrent.ExecutorService;

public class SecretsDetectorHttpHandler implements HttpHandler {
    
    private final MontoyaApi api;
    private final ExecutorService executorService;
    private final ConfigSettings configSettings;
    
    public SecretsDetectorHttpHandler(MontoyaApi api, ExecutorService executorService, ConfigSettings configSettings) {
        this.api = api;
        this.executorService = executorService;
        this.configSettings = configSettings;
    }
    
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
        
        // Submit the response for secret scanning
        executorService.submit(() -> scanResponseForSecrets(responseReceived));
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    private void scanResponseForSecrets(HttpResponseReceived responseReceived) {
        try {
            // Save response to temp file
            File tempFile = api.utilities().copyToTempFile(responseReceived.response().toByteArray());
            
            // Create scanner and scan the file
            SecretsDetector scanner = new SecretsDetector(api);
            ScanResult result = scanner.scanFile(tempFile, responseReceived);
            
            // Process scan results
            if (result.hasSecrets()) {
                api.logging().logToOutput("Secrets found in response from: " + responseReceived.initiatingRequest().url());
                
                // Mark the request in the UI
                responseReceived.annotations().setHighlightColor(burp.api.montoya.core.HighlightColor.RED);
                responseReceived.annotations().setNotes("Secrets detected: " + result.getSecretCount());
                
                // Report detailed findings
                for (Secret secret : result.getSecrets()) {
                    api.logging().logToOutput("Secret found: " + secret.getType() + " at line " + secret.getLineNumber());
                }
            }
            
            // Clean up temp file
            if (!tempFile.delete()) {
                api.logging().logToError("Failed to delete temporary file: " + tempFile.getAbsolutePath());
            }
            
        } catch (Exception e) {
            api.logging().logToError("Error scanning response: " + e.getMessage());
            e.printStackTrace();
        }
    }
}