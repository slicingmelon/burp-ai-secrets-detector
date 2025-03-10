package slicingmelon.aisecretsdetector;

public class ConfigSettings {
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