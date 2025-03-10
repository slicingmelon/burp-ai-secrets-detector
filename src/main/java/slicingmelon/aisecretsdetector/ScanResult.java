package slicingmelon.aisecretsdetector;

import burp.api.montoya.http.handler.HttpResponseReceived;

import java.util.List;

public class ScanResult {
    private final HttpResponseReceived responseReceived;
    private final List<Secret> secrets;
    
    public ScanResult(HttpResponseReceived responseReceived, List<Secret> secrets) {
        this.responseReceived = responseReceived;
        this.secrets = secrets;
    }
    
    public HttpResponseReceived getResponseReceived() {
        return responseReceived;
    }
    
    public List<Secret> getSecrets() {
        return secrets;
    }
    
    public boolean hasSecrets() {
        return !secrets.isEmpty();
    }
    
    public int getSecretCount() {
        return secrets.size();
    }
}