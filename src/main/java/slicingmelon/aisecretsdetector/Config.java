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
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
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
    private Toml config;
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
        this.config = new Toml(); // Always initialize config to prevent null
        
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
            Config minimalConfig = new Config();
            minimalConfig.patterns = new ArrayList<>();
            minimalConfig.settings = new Settings();
            minimalConfig.config = new Toml();
            minimalConfig.api = null;
            minimalConfig.onConfigChangedCallback = null;
            return minimalConfig;
        } catch (Exception e) {
            // If even minimal creation fails, create an absolutely basic instance
            Config emergency = new Config();
            emergency.patterns = new ArrayList<>();
            emergency.settings = new Settings();
            emergency.config = new Toml();
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
                this.config = new Toml().read(savedConfig);
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
            this.config = new Toml();
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
                Logger.logCriticalError("Default config file not found in resources");
                // Create empty config to avoid null pointer exceptions
                this.config = new Toml();
            }
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load default configuration: " + e.getMessage());
            // Create empty config to avoid null pointer exceptions
            this.config = new Toml();
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
        configVersion = config.getString("version", "unknown");
    }
    
    private void parseSettings() {
        if (config == null) {
            Logger.logCriticalError("Cannot parse settings: config is null");
            return;
        }
        
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
                        Logger.logCriticalError("Invalid tool type: " + toolStr);
                    }
                }
                settings.setEnabledTools(enabledTools);
            }
        }
    }
    
    private void parsePatterns() {
        patterns.clear();
        
        if (config == null) {
            Logger.logCriticalError("Cannot parse patterns: config is null");
            return;
        }
        
        List<Map<String, Object>> patternMaps = config.getList("patterns");
        if (patternMaps != null) {
            for (Map<String, Object> patternMap : patternMaps) {
                String name = (String) patternMap.get("name");
                String prefix = (String) patternMap.get("prefix");
                String pattern = (String) patternMap.get("pattern");
                String suffix = (String) patternMap.get("suffix");
                
                if (name != null && !name.isEmpty() && pattern != null && !pattern.isEmpty()) {
                    try {
                        // Handle dynamic patterns before compiling
                        if (name.equals("Generic Secret") || name.equals("Generic Secret v2")) {
                            // Use replace() instead of String.format() to avoid issues with literal % characters
                            pattern = pattern.replace("%d,%d", 
                                settings.getGenericSecretMinLength() + "," + settings.getGenericSecretMaxLength());
                        }
                        
                        PatternConfig patternConfig = new PatternConfig(name, prefix, pattern, suffix);
                        patterns.add(patternConfig);
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
            // Convert current configuration to TOML format
            Map<String, Object> configMap = new HashMap<>();
            
            // Add version (use current extension version)
            configMap.put("version", getCurrentExtensionVersion());
            
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
            
            // Add patterns (ensure patterns is not null)
            List<Map<String, Object>> patternsList = new ArrayList<>();
            if (patterns != null) {
                for (PatternConfig pattern : patterns) {
                    if (pattern != null) {
                        Map<String, Object> patternMap = new HashMap<>();
                        patternMap.put("name", pattern.getName());
                        patternMap.put("prefix", pattern.getPrefix() != null ? pattern.getPrefix() : "");
                        patternMap.put("pattern", pattern.getPattern());
                        patternMap.put("suffix", pattern.getSuffix() != null ? pattern.getSuffix() : "");
                        patternsList.add(patternMap);
                    }
                }
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
     * @param tomlString The TOML content to write
     */
    private void autoSyncExternalConfigFile(String tomlString) {
        try {
            String configFilePath = getDefaultConfigFilePath();
            Path configPath = Paths.get(configFilePath);
            
            // Create directory if it doesn't exist
            Files.createDirectories(configPath.getParent());
            
            // Write the TOML content to file
            Files.write(configPath, tomlString.getBytes());
            
            Logger.logMsg("Auto-synced configuration to " + configFilePath);
            
        } catch (Exception e) {
            Logger.logErrorMsg("Failed to auto-sync config file: " + e.getMessage());
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
            
            // Save to persistence and auto-sync to external file
            saveConfig();
            
            // Also overwrite external config file with fresh default
            String configFilePath = getDefaultConfigFilePath();
            copyDefaultConfigToFile(configFilePath);
            
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
        // Generate TOML content (same as saveConfig but to file)
        Map<String, Object> configMap = new HashMap<>();
        
        // Add version (use current extension version)
        configMap.put("version", getCurrentExtensionVersion());
        
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
        
        // Write to file
        try (FileWriter fileWriter = new FileWriter(filePath)) {
            fileWriter.write(tomlString);
        }
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
            this.config = new Toml().read(fileReader);
            
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
     * Initialize external config file on first install
     * Copies default-config.toml to config.toml only if config.toml doesn't exist
     */
    public void initializeExternalConfigFile() {
        String configFilePath = getDefaultConfigFilePath();
        
        // Only create if config.toml doesn't exist (first install)
        if (!Files.exists(Paths.get(configFilePath))) {
            try {
                // Copy default config to external location
                copyDefaultConfigToFile(configFilePath);
                Logger.logCritical("First install: Created config file at " + configFilePath);
            } catch (IOException e) {
                Logger.logCriticalError("Failed to create initial config file: " + e.getMessage());
            }
        }
    }
    
    /**
     * Copy the default configuration to the specified file path
     * @param filePath The destination file path
     * @throws IOException If file operations fail
     */
    private void copyDefaultConfigToFile(String filePath) throws IOException {
        // Load default config from resources
        InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH);
        if (defaultConfigStream == null) {
            throw new IOException("Default config not found in resources");
        }
        
        try {
            // Read default config content
            byte[] configBytes = defaultConfigStream.readAllBytes();
            
            // Ensure directory exists
            Path configPath = Paths.get(filePath);
            Files.createDirectories(configPath.getParent());
            
            // Write to file
            Files.write(configPath, configBytes);
            
        } finally {
            defaultConfigStream.close();
        }
    }
    
} 