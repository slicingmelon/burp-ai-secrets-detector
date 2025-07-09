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
import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.file.FileConfig;
import com.electronwill.nightconfig.toml.TomlFormat;
import com.electronwill.nightconfig.toml.TomlParser;
import com.electronwill.nightconfig.toml.TomlWriter;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.io.FileReader;
import java.io.StringWriter;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Config {
    private static final String CONFIG_KEY = "config_toml";
    private static final String CONFIG_VERSION_KEY = "config_version";
    private static final String DEFAULT_CONFIG_PATH = "/default-config.toml";
    
    private MontoyaApi api;
    private static Config instance;
    private CommentedConfig config;
    private List<PatternConfig> patterns;
    private Settings settings;
    private String configVersion; // Version of the current config
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
        this.settings = new Settings(); // Always initialize settings first
        this.config = TomlFormat.newConfig(); // Always initialize config to prevent null
        
        // Only load config if we have an API instance
        if (api != null) {
            try {
                loadConfig();
            } catch (Exception e) {
                Logger.logCriticalError("Error during config loading, using defaults: " + e.getMessage());
                // Keep the default settings and empty config we already initialized
            }
        }
    }
    
    public static Config getInstance() {
        if (instance == null) {
            // Create a minimal Config instance with default settings if none exists
            // This prevents null pointer exceptions
            try {
                instance = new Config(null, null);
            } catch (Exception e) {
                // If even that fails, create a truly minimal instance
                instance = createMinimalInstance();
            }
        }
        return instance;
    }
    
    public static Config initialize(MontoyaApi api, Runnable onConfigChangedCallback) {
        try {
            if (instance == null) {
                instance = new Config(api, onConfigChangedCallback);
            } else {
                // Update existing instance with new API and callback
                instance.api = api;
                instance.onConfigChangedCallback = onConfigChangedCallback;
                // Reload config with the new API
                instance.loadConfig();
            }
            return instance;
        } catch (Exception e) {
            // If initialization fails, create a minimal working instance
            if (api != null) {
                api.logging().logToError("Failed to initialize Config properly: " + e.getMessage());
            }
            if (instance == null) {
                instance = createMinimalInstance();
                instance.api = api;
                instance.onConfigChangedCallback = onConfigChangedCallback;
            }
            return instance;
        }
    }
    
    /**
     * Creates a minimal Config instance with default settings to prevent null pointer exceptions
     */
    private static Config createMinimalInstance() {
        try {
            Config minimalConfig = new Config(null, null);
            minimalConfig.patterns = new ArrayList<>();
            minimalConfig.settings = new Settings();
            minimalConfig.config = TomlFormat.newConfig();
            minimalConfig.api = null;
            minimalConfig.onConfigChangedCallback = null;
            return minimalConfig;
        } catch (Exception e) {
            // If even minimal creation fails, create an absolutely basic instance
            Config emergency = new Config(null, null);
            emergency.patterns = new ArrayList<>();
            emergency.settings = new Settings();
            emergency.config = TomlFormat.newConfig();
            return emergency;
        }
    }
    
    /**
     * Private constructor for creating minimal instances
     */
    private Config() {
        // Minimal constructor for fallback instances
    }
    
    private void loadConfig() {
        try {
            // First, try to load from persistence
            if (api == null) {
                loadDefaultConfig();
                return;
            }
            
            PersistedObject persistedData = api.persistence().extensionData();
            String savedConfig = persistedData.getString(CONFIG_KEY);
            
            if (savedConfig != null && !savedConfig.isEmpty()) {
                // Parse the persisted config
                TomlParser parser = TomlFormat.instance().createParser();
                this.config = parser.parse(new StringReader(savedConfig));
                parseConfig();
            } else {
                // Load default config from resources
                loadDefaultConfig();
            }
            
            // Initialize external config file on first install (only if it doesn't exist)
            initializeExternalConfigFile();
            
            // Apply dynamic pattern replacement for generic secrets
            applyDynamicPatterns();
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load configuration: " + e.getMessage());
            e.printStackTrace();
            // Fallback to default config
            loadDefaultConfig();
        }
        
        // Ensure config is never null
        if (this.config == null) {
            this.config = TomlFormat.newConfig();
        }
    }
    
    private void loadDefaultConfig() {
        try {
            InputStream configStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH);
            if (configStream != null) {
                TomlParser parser = TomlFormat.instance().createParser();
                this.config = parser.parse(configStream);
                parseConfig();
                // Save default config to persistence
                saveConfig();
            } else {
                Logger.logCriticalError("Default config file not found in resources");
                // Create empty config to avoid null pointer exceptions
                this.config = TomlFormat.newConfig();
            }
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load default configuration: " + e.getMessage());
            // Create empty config to avoid null pointer exceptions
            this.config = TomlFormat.newConfig();
        }
    }
    
    private void parseConfig() {
        // Parse version first
        parseVersion();
        
        // Parse settings
        parseSettings();
        
        // Parse patterns
        parsePatterns();
    }
    
    private void parseVersion() {
        if (config == null) {
            Logger.logCriticalError("Cannot parse version: config is null");
            configVersion = "unknown";
            return;
        }
        
        // Get version from config, fallback to "unknown" if not found
        String version = config.get("version");
        configVersion = version != null ? version : "unknown";
    }
    
    private void parseSettings() {
        if (config == null) {
            Logger.logCriticalError("Cannot parse settings: config is null");
            return;
        }
        
        CommentedConfig settingsConfig = config.get("settings");
        if (settingsConfig != null) {
            
            Integer workers = settingsConfig.get("workers");
            if (workers != null) {
                settings.setWorkers(workers);
            }
            
            Boolean inScopeOnly = settingsConfig.get("in_scope_only");
            if (inScopeOnly != null) {
                settings.setInScopeOnly(inScopeOnly);
            }
            
            Boolean loggingEnabled = settingsConfig.get("logging_enabled");
            if (loggingEnabled != null) {
                settings.setLoggingEnabled(loggingEnabled);
            }
            
            Boolean randomnessAlgorithmEnabled = settingsConfig.get("randomness_algorithm_enabled");
            if (randomnessAlgorithmEnabled != null) {
                settings.setRandomnessAlgorithmEnabled(randomnessAlgorithmEnabled);
            }
            
            Integer genericSecretMinLength = settingsConfig.get("generic_secret_min_length");
            if (genericSecretMinLength != null) {
                settings.setGenericSecretMinLength(genericSecretMinLength);
            }
            
            Integer genericSecretMaxLength = settingsConfig.get("generic_secret_max_length");
            if (genericSecretMaxLength != null) {
                settings.setGenericSecretMaxLength(genericSecretMaxLength);
            }
            
            Integer duplicateThreshold = settingsConfig.get("duplicate_threshold");
            if (duplicateThreshold != null) {
                settings.setDuplicateThreshold(duplicateThreshold);
            }
            
            Integer maxHighlightsPerSecret = settingsConfig.get("max_highlights_per_secret");
            if (maxHighlightsPerSecret != null) {
                settings.setMaxHighlightsPerSecret(maxHighlightsPerSecret);
            }
            
            // Parse excluded file extensions
            List<String> excludedExtensions = settingsConfig.get("excluded_file_extensions");
            if (excludedExtensions != null) {
                Set<String> excludedExtensionsSet = new HashSet<>();
                excludedExtensionsSet.addAll(excludedExtensions);
                settings.setExcludedFileExtensions(excludedExtensionsSet);
            }
            
            // Parse enabled tools
            List<String> enabledTools = settingsConfig.get("enabled_tools");
            if (enabledTools != null) {
                Set<ToolType> enabledToolsSet = new HashSet<>();
                for (String toolName : enabledTools) {
                    try {
                        enabledToolsSet.add(ToolType.valueOf(toolName));
                    } catch (IllegalArgumentException e) {
                        Logger.logCriticalError("Invalid tool type: " + toolName);
                    }
                }
                settings.setEnabledTools(enabledToolsSet);
            }
        }
    }
    
    private void parsePatterns() {
        patterns.clear();
        
        if (config == null) {
            Logger.logCriticalError("Cannot parse patterns: config is null");
            return;
        }
        
        List<CommentedConfig> patternsConfig = config.get("patterns");
        if (patternsConfig != null) {
            for (CommentedConfig patternConfig : patternsConfig) {
                String name = patternConfig.get("name");
                String prefix = patternConfig.get("prefix");
                String pattern = patternConfig.get("pattern");
                String suffix = patternConfig.get("suffix");
                
                if (name != null && !name.isEmpty() && pattern != null && !pattern.isEmpty()) {
                    try {
                        // Handle dynamic patterns before compiling
                        if (name.equals("Generic Secret") || name.equals("Generic Secret v2")) {
                            // Use replace() instead of String.format() to avoid issues with literal % characters
                            pattern = pattern.replace("%d,%d", 
                                settings.getGenericSecretMinLength() + "," + settings.getGenericSecretMaxLength());
                        }
                        
                        PatternConfig patternConfigObj = new PatternConfig(name, prefix, pattern, suffix);
                        patterns.add(patternConfigObj);
                    } catch (Exception e) {
                        Logger.logCriticalError("Failed to compile pattern '" + name + "': " + e.getMessage());
                    }
                }
            }
        }
    }
    
    private void applyDynamicPatterns() {
        // Re-parse patterns to apply updated dynamic values
        parsePatterns();
    }
    
    public void saveConfig() {
        try {
            // Can't save config without API or settings
            if (api == null || settings == null) {
                Logger.logCriticalError("Cannot save config: API or settings is null");
                return;
            }
            
            // Don't save if we're still initializing (this.config might be null)
            if (this.config == null) {
                Logger.logCriticalError("Cannot save config: config object is null (still initializing?)");
                return;
            }
            // Convert current configuration to TOML format
            CommentedConfig configMap = TomlFormat.newConfig();
            
            // Add version (use current extension version)
            configMap.set("version", getCurrentExtensionVersion());
            
            // Add settings
            CommentedConfig settingsMap = TomlFormat.newConfig();
            settingsMap.set("workers", settings.getWorkers());
            settingsMap.set("in_scope_only", settings.isInScopeOnly());
            settingsMap.set("logging_enabled", settings.isLoggingEnabled());
            settingsMap.set("randomness_algorithm_enabled", settings.isRandomnessAlgorithmEnabled());
            settingsMap.set("generic_secret_min_length", settings.getGenericSecretMinLength());
            settingsMap.set("generic_secret_max_length", settings.getGenericSecretMaxLength());
            settingsMap.set("duplicate_threshold", settings.getDuplicateThreshold());
            settingsMap.set("max_highlights_per_secret", settings.getMaxHighlightsPerSecret());
            settingsMap.set("excluded_file_extensions", new ArrayList<>(settings.getExcludedFileExtensions()));
            
            List<String> enabledToolsStr = new ArrayList<>();
            for (ToolType tool : settings.getEnabledTools()) {
                enabledToolsStr.add(tool.name());
            }
            settingsMap.set("enabled_tools", enabledToolsStr);
            
            configMap.set("settings", settingsMap);
            
            // Add patterns (ensure patterns is not null)
            List<CommentedConfig> patternsList = new ArrayList<>();
            if (patterns != null) {
                Logger.logCritical("Saving config with " + patterns.size() + " patterns");
                for (PatternConfig pattern : patterns) {
                    if (pattern != null) {
                        // Use LinkedHashMap to preserve field order: name, prefix, pattern, suffix
                        CommentedConfig patternMap = TomlFormat.newConfig(java.util.LinkedHashMap::new);
                        patternMap.set("name", pattern.getName());
                        patternMap.set("prefix", pattern.getPrefix() != null ? pattern.getPrefix() : "");
                        patternMap.set("pattern", pattern.getPattern());
                        patternMap.set("suffix", pattern.getSuffix() != null ? pattern.getSuffix() : "");
                        patternsList.add(patternMap);
                    }
                }
            } else {
                Logger.logCritical("Warning: Saving config with null patterns list");
            }
            configMap.set("patterns", patternsList);
            
            // Convert to TOML string
            TomlWriter writer = createConfiguredTomlWriter();
            StringWriter stringWriter = new StringWriter();
            writer.write(configMap, stringWriter);
            String tomlString = stringWriter.toString();
            
            // Save to persistence
            PersistedObject persistedData = api.persistence().extensionData();
            persistedData.setString(CONFIG_KEY, tomlString);
            
            // Also auto-sync to external config file
            autoSyncExternalConfigFile(tomlString);
            
            // Notify of config change
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to save configuration: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Automatically sync the external config.toml file when settings change
     * NightConfig generates proper TOML sections with setHideRedundantLevels(false)
     * @param tomlString The TOML content to write (we use this directly now)
     */
    private void autoSyncExternalConfigFile(String tomlString) {
        try {
            String configFilePath = getDefaultConfigFilePath();
            Path configPath = Paths.get(configFilePath);
            
            // Create directory if it doesn't exist
            Files.createDirectories(configPath.getParent());
            
            // Use the properly formatted TOML string from NightConfig
            Files.write(configPath, tomlString.getBytes());
            
            Logger.logMsg("Auto-synced configuration to " + configFilePath);
            
        } catch (Exception e) {
            Logger.logErrorMsg("Failed to auto-sync config file: " + e.getMessage());
        }
    }
    
    /**
     * Generate proper TOML content with correct formatting and triple-quote literals
     * This method is kept for backwards compatibility but now uses NightConfig's proper formatting
     * @return Properly formatted TOML string
     */
    private String generateProperTomlContent() {
        try {
            // Create config using NightConfig
            CommentedConfig configMap = TomlFormat.newConfig();
            
            // Add version
            configMap.set("version", getCurrentExtensionVersion());
            
            // Add settings
            CommentedConfig settingsMap = TomlFormat.newConfig();
            settingsMap.set("excluded_file_extensions", new ArrayList<>(settings.getExcludedFileExtensions()));
            settingsMap.set("workers", settings.getWorkers());
            settingsMap.set("in_scope_only", settings.isInScopeOnly());
            settingsMap.set("logging_enabled", settings.isLoggingEnabled());
            settingsMap.set("randomness_algorithm_enabled", settings.isRandomnessAlgorithmEnabled());
            settingsMap.set("generic_secret_min_length", settings.getGenericSecretMinLength());
            settingsMap.set("generic_secret_max_length", settings.getGenericSecretMaxLength());
            settingsMap.set("duplicate_threshold", settings.getDuplicateThreshold());
            settingsMap.set("max_highlights_per_secret", settings.getMaxHighlightsPerSecret());
            
            List<String> enabledToolsStr = new ArrayList<>();
            for (ToolType tool : settings.getEnabledTools()) {
                enabledToolsStr.add(tool.name());
            }
            settingsMap.set("enabled_tools", enabledToolsStr);
            
            configMap.set("settings", settingsMap);
            
            // Add patterns
            List<CommentedConfig> patternsList = new ArrayList<>();
            if (patterns != null) {
                for (PatternConfig pattern : patterns) {
                    // Use LinkedHashMap to preserve field order: name, prefix, pattern, suffix
                    CommentedConfig patternMap = TomlFormat.newConfig(java.util.LinkedHashMap::new);
                    patternMap.set("name", pattern.getName());
                    patternMap.set("prefix", pattern.getPrefix() != null ? pattern.getPrefix() : "");
                    patternMap.set("pattern", pattern.getPattern());
                    patternMap.set("suffix", pattern.getSuffix() != null ? pattern.getSuffix() : "");
                    patternsList.add(patternMap);
                }
            }
            configMap.set("patterns", patternsList);
            
            // Convert to TOML string using NightConfig
            TomlWriter writer = createConfiguredTomlWriter();
            StringWriter stringWriter = new StringWriter();
            writer.write(configMap, stringWriter);
            return stringWriter.toString();
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to generate proper TOML content: " + e.getMessage());
            return "# Error generating TOML content\n";
        }
    }
    
    public void resetToDefaults() {
        loadDefaultConfig();
        applyDynamicPatterns();
        saveConfig(); // This will also auto-sync to external file
    }
    
    /**
     * Reset configuration to defaults: default-config -> config.toml -> persistence
     * Overwrites both persistence and external config file
     */
    public void resetToDefaultsComplete() {
        try {
            // Load default config
            loadDefaultConfig();
            applyDynamicPatterns();
            
            // Save to persistence and auto-sync to external file (uses template approach)
            saveConfig();
            
            Logger.logCritical("Configuration reset to defaults");
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to reset configuration to defaults: " + e.getMessage());
        }
    }
    
    /**
     * Update configuration with new defaults while preserving user customizations
     * default-config -> config.toml, then merge with existing persistence
     */
    public void updateAndMergeWithDefaults() {
        try {
            // Save current user settings
            Settings currentSettings = new Settings();
            if (settings != null) {
                // Copy current user settings
                currentSettings.setWorkers(settings.getWorkers());
                currentSettings.setInScopeOnly(settings.isInScopeOnly());
                currentSettings.setLoggingEnabled(settings.isLoggingEnabled());
                currentSettings.setRandomnessAlgorithmEnabled(settings.isRandomnessAlgorithmEnabled());
                currentSettings.setGenericSecretMinLength(settings.getGenericSecretMinLength());
                currentSettings.setGenericSecretMaxLength(settings.getGenericSecretMaxLength());
                currentSettings.setDuplicateThreshold(settings.getDuplicateThreshold());
                currentSettings.setMaxHighlightsPerSecret(settings.getMaxHighlightsPerSecret());
                currentSettings.setExcludedFileExtensions(new HashSet<>(settings.getExcludedFileExtensions()));
                currentSettings.setEnabledTools(new HashSet<>(settings.getEnabledTools()));
            }
            
            // Save current user patterns (custom ones)
            List<PatternConfig> currentPatterns = new ArrayList<>();
            if (patterns != null) {
                currentPatterns.addAll(patterns);
            }
            
            // Load fresh defaults
            loadDefaultConfig();
            applyDynamicPatterns();
            
            // Merge user settings back
            if (currentSettings != null) {
                settings.setWorkers(currentSettings.getWorkers());
                settings.setInScopeOnly(currentSettings.isInScopeOnly());
                settings.setLoggingEnabled(currentSettings.isLoggingEnabled());
                settings.setRandomnessAlgorithmEnabled(currentSettings.isRandomnessAlgorithmEnabled());
                settings.setGenericSecretMinLength(currentSettings.getGenericSecretMinLength());
                settings.setGenericSecretMaxLength(currentSettings.getGenericSecretMaxLength());
                settings.setDuplicateThreshold(currentSettings.getDuplicateThreshold());
                settings.setMaxHighlightsPerSecret(currentSettings.getMaxHighlightsPerSecret());
                settings.setExcludedFileExtensions(currentSettings.getExcludedFileExtensions());
                settings.setEnabledTools(currentSettings.getEnabledTools());
            }
            
            // Merge patterns: Add user patterns that don't exist in defaults
            if (currentPatterns != null && patterns != null) {
                Set<String> defaultPatternNames = patterns.stream()
                    .map(PatternConfig::getName)
                    .collect(Collectors.toSet());
                
                // Add custom user patterns that are not in defaults
                for (PatternConfig userPattern : currentPatterns) {
                    if (!defaultPatternNames.contains(userPattern.getName())) {
                        patterns.add(userPattern);
                    }
                }
            }
            
            // Save merged configuration
            saveConfig();
            
            Logger.logCritical("Configuration updated and merged with defaults");
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to update and merge configuration: " + e.getMessage());
        }
    }
    
    public void reloadConfig() {
        loadConfig();
        // Notify of config change
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
    }
    
    public Settings getSettings() {
        if (settings == null) {
            // Initialize with defaults if not yet loaded
            settings = new Settings();
        }
        return settings;
    }
    
    public List<PatternConfig> getPatterns() {
        return patterns;
    }
    
    public String getConfigVersion() {
        return configVersion != null ? configVersion : "unknown";
    }
    
    public String getCurrentExtensionVersion() {
        try {
            return VersionUtil.getVersion();
        } catch (Exception e) {
            Logger.logCriticalError("Error getting extension version: " + e.getMessage());
            return "1.7.1"; // Fallback to current version
        }
    }
    
    public boolean isConfigUpToDate() {
        String currentVersion = getCurrentExtensionVersion();
        String configVer = getConfigVersion();
        return currentVersion.equals(configVer);
    }
    
    public boolean isConfigVersionNewer() {
        String currentVersion = getCurrentExtensionVersion();
        String configVer = getConfigVersion();
        return compareVersions(configVer, currentVersion) > 0;
    }
    
    /**
     * Compare two version strings (simple string comparison for now)
     * @param version1 First version string
     * @param version2 Second version string  
     * @return negative if version1 < version2, 0 if equal, positive if version1 > version2
     */
    private int compareVersions(String version1, String version2) {
        if (version1 == null) version1 = "unknown";
        if (version2 == null) version2 = "unknown";
        
        if ("unknown".equals(version1) || "unknown".equals(version2)) {
            return version1.compareTo(version2);
        }
        
        // Simple string comparison for now - could be enhanced with semantic versioning
        return version1.compareTo(version2);
    }
    
    public void updateGenericSecretLengths(int minLength, int maxLength) {
        settings.setGenericSecretMinLength(minLength);
        settings.setGenericSecretMaxLength(maxLength);
        applyDynamicPatterns();
        saveConfig();
    }
    
    /**
     * Export current configuration to a TOML file
     * @param filePath The path where to save the config file
     * @throws IOException If file operations fail
     */
    public void exportConfigToFile(String filePath) throws IOException {
        // Generate TOML content using NightConfig
        CommentedConfig configMap = TomlFormat.newConfig();
        
        // Add version (use current extension version)
        configMap.set("version", getCurrentExtensionVersion());
        
        // Add settings
        CommentedConfig settingsMap = TomlFormat.newConfig();
        settingsMap.set("workers", settings.getWorkers());
        settingsMap.set("in_scope_only", settings.isInScopeOnly());
        settingsMap.set("logging_enabled", settings.isLoggingEnabled());
        settingsMap.set("randomness_algorithm_enabled", settings.isRandomnessAlgorithmEnabled());
        settingsMap.set("generic_secret_min_length", settings.getGenericSecretMinLength());
        settingsMap.set("generic_secret_max_length", settings.getGenericSecretMaxLength());
        settingsMap.set("duplicate_threshold", settings.getDuplicateThreshold());
        settingsMap.set("max_highlights_per_secret", settings.getMaxHighlightsPerSecret());
        settingsMap.set("excluded_file_extensions", new ArrayList<>(settings.getExcludedFileExtensions()));
        
        List<String> enabledToolsStr = new ArrayList<>();
        for (ToolType tool : settings.getEnabledTools()) {
            enabledToolsStr.add(tool.name());
        }
        settingsMap.set("enabled_tools", enabledToolsStr);
        
        configMap.set("settings", settingsMap);
        
        // Add patterns
        List<CommentedConfig> patternsList = new ArrayList<>();
        if (patterns != null) {
            Logger.logCritical("Exporting config with " + patterns.size() + " patterns");
            for (PatternConfig pattern : patterns) {
                if (pattern != null) {
                    CommentedConfig patternMap = TomlFormat.newConfig();
                    patternMap.set("name", pattern.getName());
                    patternMap.set("prefix", pattern.getPrefix() != null ? pattern.getPrefix() : "");
                    patternMap.set("pattern", pattern.getPattern());
                    patternMap.set("suffix", pattern.getSuffix() != null ? pattern.getSuffix() : "");
                    patternsList.add(patternMap);
                }
            }
        } else {
            Logger.logCritical("Warning: Exporting config with null patterns list");
        }
        configMap.set("patterns", patternsList);
        
        // Convert to TOML string and write to file
        TomlWriter writer = createConfiguredTomlWriter();
        StringWriter stringWriter = new StringWriter();
        writer.write(configMap, stringWriter);
        String tomlString = stringWriter.toString();
        Files.write(Paths.get(filePath), tomlString.getBytes());
    }
    
    /**
     * Import configuration from a TOML file
     * @param filePath The path to the config file to import
     * @throws IOException If file operations fail
     */
    public void importConfigFromFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("Config file not found: " + filePath);
        }
        
        try (FileReader fileReader = new FileReader(file)) {
            // Parse the TOML file
            TomlParser parser = TomlFormat.instance().createParser();
            this.config = parser.parse(fileReader);
            
            // Parse the loaded config
            parseConfig();
            
            // Apply dynamic patterns
            applyDynamicPatterns();
            
            // Save to Burp persistence (primary storage)
            saveConfig();
            
            // Notify of config change
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
        }
    }
    
    /**
     * Get the default config file path for export/import
     * Following HaE extension pattern for cross-platform compatibility
     * @return The recommended file path for config export
     */
    public String getDefaultConfigFilePath() {
        String userHome = System.getProperty("user.home");
        String configDir;
        
        // Cross-platform config directory (following HaE pattern)
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            // Windows: %USERPROFILE%/burp-ai-secrets-detector/
            configDir = Paths.get(userHome, "burp-ai-secrets-detector").toString();
        } else {
            // Linux/Mac: ~/burp-ai-secrets-detector/
            configDir = Paths.get(userHome, "burp-ai-secrets-detector").toString();
        }
        
        // Ensure directory exists
        try {
            Files.createDirectories(Paths.get(configDir));
        } catch (IOException e) {
            Logger.logCriticalError("Failed to create config directory: " + e.getMessage());
        }
        
        return Paths.get(configDir, "config.toml").toString();
    }
    
    /**
     * Check if a config file exists at the default location
     * @return true if config file exists at default location
     */
    public boolean hasExportedConfigFile() {
        return Files.exists(Paths.get(getDefaultConfigFilePath()));
    }
    
    /**
     * Create and configure a TomlWriter with proper settings for regex patterns
     * @return Configured TomlWriter instance
     */
    private TomlWriter createConfiguredTomlWriter() {
        TomlWriter writer = TomlFormat.instance().createWriter();
        writer.setHideRedundantLevels(false); // Generate proper TOML sections!
        writer.setIndent(""); // No indentation - flat TOML format
        
        // Configure writer to use literal strings (triple quotes) for ALL pattern fields
        // This ensures consistent formatting like the default-config.toml
        writer.setWriteStringLiteralPredicate(str -> {
            // Use triple quotes for all strings in patterns (including empty strings)
            // This matches the format in default-config.toml exactly
            return true; // Use triple quotes for everything to match default format
        });
        
        return writer;
    }
    
    /**
     * Initialize external config file on first install
     * Creates config.toml only if it doesn't exist
     */
    public void initializeExternalConfigFile() {
        String configFilePath = getDefaultConfigFilePath();
        
        // Only create if config.toml doesn't exist (first install)
        if (!Files.exists(Paths.get(configFilePath))) {
            try {
                // Ensure patterns are loaded before exporting
                if (patterns == null || patterns.isEmpty()) {
                    Logger.logCritical("Warning: Patterns not loaded, re-parsing config before export");
                    parseConfig(); // Re-parse to ensure patterns are loaded
                }
                
                // Export current config to create initial config file
                exportConfigToFile(configFilePath);
                Logger.logCritical("First install: Created config file at " + configFilePath + " with " + 
                    (patterns != null ? patterns.size() : 0) + " patterns");
            } catch (IOException e) {
                Logger.logCriticalError("Failed to create initial config file: " + e.getMessage());
            }
        }
    }
    

    
} 