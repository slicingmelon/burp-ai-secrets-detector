/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Configuration management using TOML format
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.ToolType;
import com.moandjiezana.toml.Toml;
import com.moandjiezana.toml.TomlWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;

public class Config {
    private static final String CONFIG_KEY = "config_toml";
    private static final String DEFAULT_CONFIG_PATH = "/default-config.toml";
    
    private final MontoyaApi api;
    private static Config instance;
    private Toml config;
    private List<PatternConfig> patterns;
    private Settings settings;
    private Runnable onConfigChangedCallback;
    
    // Configuration classes
    public static class PatternConfig {
        private final String name;
        private final String prefix;
        private final String pattern;
        private final String suffix;
        private final Pattern compiledPattern;
        
        public PatternConfig(String name, String prefix, String pattern, String suffix) {
            this.name = name;
            this.prefix = prefix;
            this.pattern = pattern;
            this.suffix = suffix;
            
            // Compile the pattern based on prefix, pattern, and suffix
            String fullPattern = buildFullPattern(prefix, pattern, suffix);
            this.compiledPattern = Pattern.compile(fullPattern);
        }
        
        private String buildFullPattern(String prefix, String pattern, String suffix) {
            StringBuilder fullPattern = new StringBuilder();
            if (prefix != null && !prefix.isEmpty()) {
                fullPattern.append(prefix);
            }
            if (pattern != null && !pattern.isEmpty()) {
                fullPattern.append(pattern);
            }
            if (suffix != null && !suffix.isEmpty()) {
                fullPattern.append(suffix);
            }
            return fullPattern.toString();
        }
        
        public String getName() {
            return name;
        }
        
        public String getPrefix() {
            return prefix;
        }
        
        public String getPattern() {
            return pattern;
        }
        
        public String getSuffix() {
            return suffix;
        }
        
        public Pattern getCompiledPattern() {
            return compiledPattern;
        }
    }
    
    public static class Settings {
        private int workers;
        private boolean inScopeOnly;
        private boolean loggingEnabled;
        private boolean randomnessAlgorithmEnabled;
        private int genericSecretMinLength;
        private int genericSecretMaxLength;
        private int duplicateThreshold;
        private int maxHighlightsPerSecret;
        private Set<String> excludedFileExtensions;
        private Set<ToolType> enabledTools;
        
        public Settings() {
            // Default values
            this.workers = 15;
            this.inScopeOnly = true;
            this.loggingEnabled = false;
            this.randomnessAlgorithmEnabled = true;
            this.genericSecretMinLength = 15;
            this.genericSecretMaxLength = 80;
            this.duplicateThreshold = 5;
            this.maxHighlightsPerSecret = 3;
            this.excludedFileExtensions = new HashSet<>();
            this.enabledTools = new HashSet<>();
            
            // Set default enabled tools
            this.enabledTools.add(ToolType.TARGET);
            this.enabledTools.add(ToolType.PROXY);
            this.enabledTools.add(ToolType.SCANNER);
            this.enabledTools.add(ToolType.EXTENSIONS);
        }
        
        // Getters and setters
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
        
        public boolean isLoggingEnabled() {
            return loggingEnabled;
        }
        
        public void setLoggingEnabled(boolean loggingEnabled) {
            this.loggingEnabled = loggingEnabled;
        }
        
        public boolean isRandomnessAlgorithmEnabled() {
            return randomnessAlgorithmEnabled;
        }
        
        public void setRandomnessAlgorithmEnabled(boolean randomnessAlgorithmEnabled) {
            this.randomnessAlgorithmEnabled = randomnessAlgorithmEnabled;
        }
        
        public int getGenericSecretMinLength() {
            return genericSecretMinLength;
        }
        
        public void setGenericSecretMinLength(int genericSecretMinLength) {
            this.genericSecretMinLength = Math.max(8, genericSecretMinLength);
        }
        
        public int getGenericSecretMaxLength() {
            return genericSecretMaxLength;
        }
        
        public void setGenericSecretMaxLength(int genericSecretMaxLength) {
            this.genericSecretMaxLength = Math.min(128, genericSecretMaxLength);
        }
        
        public int getDuplicateThreshold() {
            return duplicateThreshold;
        }
        
        public void setDuplicateThreshold(int duplicateThreshold) {
            this.duplicateThreshold = Math.max(1, duplicateThreshold);
        }
        
        public int getMaxHighlightsPerSecret() {
            return maxHighlightsPerSecret;
        }
        
        public void setMaxHighlightsPerSecret(int maxHighlightsPerSecret) {
            this.maxHighlightsPerSecret = Math.max(1, maxHighlightsPerSecret);
        }
        
        public Set<String> getExcludedFileExtensions() {
            return excludedFileExtensions;
        }
        
        public void setExcludedFileExtensions(Set<String> excludedFileExtensions) {
            this.excludedFileExtensions = excludedFileExtensions;
        }
        
        public Set<ToolType> getEnabledTools() {
            return enabledTools;
        }
        
        public void setEnabledTools(Set<ToolType> enabledTools) {
            this.enabledTools = enabledTools;
        }
        
        public boolean isToolEnabled(ToolType toolType) {
            return enabledTools.contains(toolType);
        }
        
        public void setToolEnabled(ToolType toolType, boolean enabled) {
            if (enabled) {
                enabledTools.add(toolType);
            } else {
                enabledTools.remove(toolType);
            }
        }
    }
    
    private Config(MontoyaApi api, Runnable onConfigChangedCallback) {
        this.api = api;
        this.onConfigChangedCallback = onConfigChangedCallback;
        this.patterns = new ArrayList<>();
        this.settings = new Settings();
        
        loadConfig();
    }
    
    public static Config getInstance() {
        return instance;
    }
    
    public static Config initialize(MontoyaApi api, Runnable onConfigChangedCallback) {
        if (instance == null) {
            instance = new Config(api, onConfigChangedCallback);
        }
        return instance;
    }
    
    private void loadConfig() {
        try {
            // First, try to load from persistence
            PersistedObject persistedData = api.persistence().extensionData();
            String savedConfig = persistedData.getString(CONFIG_KEY);
            
            if (savedConfig != null && !savedConfig.isEmpty()) {
                // Parse the persisted config
                this.config = new Toml().read(savedConfig);
                parseConfig();
            } else {
                // Load default config from resources
                loadDefaultConfig();
            }
            
            // Apply dynamic pattern replacement for generic secrets
            applyDynamicPatterns();
            
        } catch (Exception e) {
            logError("Failed to load configuration: " + e.getMessage());
            e.printStackTrace();
            // Fallback to default config
            loadDefaultConfig();
        }
    }
    
    private void loadDefaultConfig() {
        try {
            InputStream configStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH);
            if (configStream != null) {
                this.config = new Toml().read(configStream);
                parseConfig();
                // Save default config to persistence
                saveConfig();
            } else {
                logError("Default config file not found in resources");
            }
        } catch (Exception e) {
            logError("Failed to load default configuration: " + e.getMessage());
        }
    }
    
    private void parseConfig() {
        // Parse settings
        parseSettings();
        
        // Parse patterns
        parsePatterns();
    }
    
    private void parseSettings() {
        if (config.contains("settings")) {
            Toml settingsToml = config.getTable("settings");
            
            if (settingsToml.getLong("workers") != null) {
                settings.setWorkers(settingsToml.getLong("workers").intValue());
            }
            
            if (settingsToml.getBoolean("in_scope_only") != null) {
                settings.setInScopeOnly(settingsToml.getBoolean("in_scope_only"));
            }
            
            if (settingsToml.getBoolean("logging_enabled") != null) {
                settings.setLoggingEnabled(settingsToml.getBoolean("logging_enabled"));
            }
            
            if (settingsToml.getBoolean("randomness_algorithm_enabled") != null) {
                settings.setRandomnessAlgorithmEnabled(settingsToml.getBoolean("randomness_algorithm_enabled"));
            }
            
            if (settingsToml.getLong("generic_secret_min_length") != null) {
                settings.setGenericSecretMinLength(settingsToml.getLong("generic_secret_min_length").intValue());
            }
            
            if (settingsToml.getLong("generic_secret_max_length") != null) {
                settings.setGenericSecretMaxLength(settingsToml.getLong("generic_secret_max_length").intValue());
            }
            
            if (settingsToml.getLong("duplicate_threshold") != null) {
                settings.setDuplicateThreshold(settingsToml.getLong("duplicate_threshold").intValue());
            }
            
            if (settingsToml.getLong("max_highlights_per_secret") != null) {
                settings.setMaxHighlightsPerSecret(settingsToml.getLong("max_highlights_per_secret").intValue());
            }
            
            // Parse excluded file extensions
            List<String> excludedExtensions = settingsToml.getList("excluded_file_extensions");
            if (excludedExtensions != null) {
                settings.setExcludedFileExtensions(new HashSet<>(excludedExtensions));
            }
            
            // Parse enabled tools
            List<String> enabledToolsStr = settingsToml.getList("enabled_tools");
            if (enabledToolsStr != null) {
                Set<ToolType> enabledTools = new HashSet<>();
                for (String toolStr : enabledToolsStr) {
                    try {
                        enabledTools.add(ToolType.valueOf(toolStr));
                    } catch (IllegalArgumentException e) {
                        logError("Invalid tool type: " + toolStr);
                    }
                }
                settings.setEnabledTools(enabledTools);
            }
        }
    }
    
    private void parsePatterns() {
        patterns.clear();
        
        List<Map<String, Object>> patternMaps = config.getList("patterns");
        if (patternMaps != null) {
            for (Map<String, Object> patternMap : patternMaps) {
                String name = (String) patternMap.get("name");
                String prefix = (String) patternMap.get("prefix");
                String pattern = (String) patternMap.get("pattern");
                String suffix = (String) patternMap.get("suffix");
                
                if (name != null && !name.isEmpty() && pattern != null && !pattern.isEmpty()) {
                    try {
                        PatternConfig patternConfig = new PatternConfig(name, prefix, pattern, suffix);
                        patterns.add(patternConfig);
                    } catch (Exception e) {
                        logError("Failed to compile pattern '" + name + "': " + e.getMessage());
                    }
                }
            }
        }
    }
    
    private void applyDynamicPatterns() {
        // Update generic secret patterns with dynamic length values
        for (int i = 0; i < patterns.size(); i++) {
            PatternConfig pattern = patterns.get(i);
            if (pattern.getName().equals("Generic Secret") || pattern.getName().equals("Generic Secret v2")) {
                try {
                    String dynamicPattern = String.format(pattern.getPattern(), 
                        settings.getGenericSecretMinLength(), settings.getGenericSecretMaxLength());
                    
                    PatternConfig updatedPattern = new PatternConfig(
                        pattern.getName(), 
                        pattern.getPrefix(), 
                        dynamicPattern, 
                        pattern.getSuffix()
                    );
                    patterns.set(i, updatedPattern);
                } catch (Exception e) {
                    logError("Failed to apply dynamic pattern for " + pattern.getName() + ": " + e.getMessage());
                }
            }
        }
    }
    
    public void saveConfig() {
        try {
            // Convert current configuration to TOML format
            Map<String, Object> configMap = new HashMap<>();
            
            // Add settings
            Map<String, Object> settingsMap = new HashMap<>();
            settingsMap.put("workers", settings.getWorkers());
            settingsMap.put("in_scope_only", settings.isInScopeOnly());
            settingsMap.put("logging_enabled", settings.isLoggingEnabled());
            settingsMap.put("randomness_algorithm_enabled", settings.isRandomnessAlgorithmEnabled());
            settingsMap.put("generic_secret_min_length", settings.getGenericSecretMinLength());
            settingsMap.put("generic_secret_max_length", settings.getGenericSecretMaxLength());
            settingsMap.put("duplicate_threshold", settings.getDuplicateThreshold());
            settingsMap.put("max_highlights_per_secret", settings.getMaxHighlightsPerSecret());
            settingsMap.put("excluded_file_extensions", new ArrayList<>(settings.getExcludedFileExtensions()));
            
            List<String> enabledToolsStr = new ArrayList<>();
            for (ToolType tool : settings.getEnabledTools()) {
                enabledToolsStr.add(tool.name());
            }
            settingsMap.put("enabled_tools", enabledToolsStr);
            
            configMap.put("settings", settingsMap);
            
            // Add patterns
            List<Map<String, Object>> patternsList = new ArrayList<>();
            for (PatternConfig pattern : patterns) {
                Map<String, Object> patternMap = new HashMap<>();
                patternMap.put("name", pattern.getName());
                patternMap.put("prefix", pattern.getPrefix() != null ? pattern.getPrefix() : "");
                patternMap.put("pattern", pattern.getPattern());
                patternMap.put("suffix", pattern.getSuffix() != null ? pattern.getSuffix() : "");
                patternsList.add(patternMap);
            }
            configMap.put("patterns", patternsList);
            
            // Convert to TOML string
            TomlWriter writer = new TomlWriter();
            StringWriter stringWriter = new StringWriter();
            writer.write(configMap, stringWriter);
            String tomlString = stringWriter.toString();
            
            // Save to persistence
            PersistedObject persistedData = api.persistence().extensionData();
            persistedData.setString(CONFIG_KEY, tomlString);
            
            // Notify of config change
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
            
        } catch (Exception e) {
            logError("Failed to save configuration: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public void resetToDefaults() {
        loadDefaultConfig();
        applyDynamicPatterns();
    }
    
    public void reloadConfig() {
        loadConfig();
        // Notify of config change
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
    }
    
    public Settings getSettings() {
        return settings;
    }
    
    public List<PatternConfig> getPatterns() {
        return patterns;
    }
    
    public void updateGenericSecretLengths(int minLength, int maxLength) {
        settings.setGenericSecretMinLength(minLength);
        settings.setGenericSecretMaxLength(maxLength);
        applyDynamicPatterns();
        saveConfig();
    }
    
    private void logError(String message) {
        if (api != null) {
            try {
                AISecretsDetector detector = AISecretsDetector.getInstance();
                if (detector != null) {
                    detector.logMsgError(message);
                } else {
                    System.err.println(message);
                }
            } catch (Exception e) {
                System.err.println(message);
            }
        } else {
            System.err.println(message);
        }
    }
} 