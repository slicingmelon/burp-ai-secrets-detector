/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Configuration management using TOML format
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.file.CommentedFileConfig;
import com.electronwill.nightconfig.core.io.WritingMode;
import com.electronwill.nightconfig.toml.TomlFormat;
import com.electronwill.nightconfig.toml.TomlParser;
import com.electronwill.nightconfig.toml.TomlWriter;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

public class Config {
    private static final String DEFAULT_CONFIG_PATH = "/default-config.toml";
    
    private MontoyaApi api;
    private static Config instance;
    private CommentedFileConfig fileConfig; // File-based config is the source of truth
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
            try {
                this.compiledPattern = Pattern.compile(fullPattern);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid regex in pattern '" + name + "': " + e.getMessage(), e);
            }
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
    
    /**
     * Create an empty CommentedConfig with proper settings for TOML format
     * Preserves insertion order and supports comments
     */
    private static CommentedConfig createEmptyConfig() {
        // Enable insertion order preservation globally
        System.setProperty("nightconfig.preserveInsertionOrder", "true");
        
        // Create a commented config with TOML format and insertion order preserved
        return TomlFormat.newConcurrentConfig();
    }
    
    private Config(MontoyaApi api, Runnable onConfigChangedCallback) {
        this.api = api;
        this.onConfigChangedCallback = onConfigChangedCallback;
        this.patterns = new ArrayList<>();
        this.settings = new Settings(); // Always initialize settings first

        // Set system property to preserve insertion order
        System.setProperty("nightconfig.preserveInsertionOrder", "true");
        
        // Only load config if we have an API instance
        if (api != null) {
            try {
                loadConfig();
            } catch (Exception e) {
                Logger.logCriticalError("Error during config loading, using defaults: " + e.getMessage());
                // Fallback to in-memory default config
                loadDefaultConfig();
            }
        }
    }
    
    public static Config getInstance() {
        if (instance == null) {
            // Create a minimal Config instance with default settings if none exists
            // This prevents null pointer exceptions
            try {
                instance = new Config(null, null);
                // Load defaults into a temporary in-memory config
                instance.loadDefaultConfig();
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
                // Load defaults into a temporary in-memory config
                instance.loadDefaultConfig();
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
            minimalConfig.fileConfig = null; // No file config for minimal instance
            minimalConfig.api = null;
            minimalConfig.onConfigChangedCallback = null;
            return minimalConfig;
        } catch (Exception e) {
            // If even minimal creation fails, create an absolutely basic instance
            Config emergency = new Config(null, null);
            emergency.patterns = new ArrayList<>();
            emergency.settings = new Settings();
            emergency.fileConfig = null;
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
            String configFilePath = getDefaultConfigFilePath();
            Path configPath = Paths.get(configFilePath);

            // If config file doesn't exist, create it from the default resource.
            if (!Files.exists(configPath)) {
                Logger.logCritical("Config file not found. Creating from default resource: " + configPath);
                try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
                    if (defaultConfigStream == null) {
                        throw new IOException("Default config resource not found: " + DEFAULT_CONFIG_PATH);
                    }
                    Files.createDirectories(configPath.getParent());
                    Files.copy(defaultConfigStream, configPath);
                } catch (IOException e) {
                    Logger.logCriticalError("Failed to create config file from default: " + e.getMessage());
                    // Stop loading if creation fails
                    loadDefaultConfig(); // Fallback to in-memory default
                    return;
                }
            }

            // Configure the TomlFormat with our custom writer
            TomlFormat tomlFormat = TomlFormat.instance();
            
            this.fileConfig = CommentedFileConfig.builder(configPath, tomlFormat)
                .writingMode(WritingMode.REPLACE) // REPLACE is needed to write comments correctly.
                .preserveInsertionOrder()
                .build();

            fileConfig.load();
            
            parseConfig();
            applyDynamicPatterns();
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load configuration from file: " + e.getMessage());
            e.printStackTrace();
            // Fallback to default config loaded in memory
            loadDefaultConfig();
        }
    }
    
    private void loadDefaultConfig() {
        try (InputStream defaultConfigStream = getClass().getClassLoader().getResourceAsStream("default-config.toml")) {
            if (defaultConfigStream != null) {
                CommentedConfig inMemoryConfig = TomlFormat.instance().createParser().parse(defaultConfigStream);
                
                // Temporarily use this in-memory config
                this.fileConfig = null; // No file, so set to null
                parseConfig(inMemoryConfig); // Parse from this object
                applyDynamicPatterns();
            } else {
                Logger.logCriticalError("Default config file not found in resources");
                this.settings = new Settings();
                this.patterns = new ArrayList<>();
            }
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load default configuration: " + e.getMessage());
            this.settings = new Settings();
            this.patterns = new ArrayList<>();
        }
    }
    
    private void parseConfig() {
        if (fileConfig == null) {
            Logger.logCriticalError("Cannot parse config: fileConfig is null.");
            return;
        }
        parseConfig(fileConfig);
    }
    
    private void parseConfig(CommentedConfig config) {
        // Parse version first
        parseVersion(config);
        
        // Parse settings
        parseSettings(config);
        
        // Parse patterns
        parsePatterns(config);
    }
    
    private void parseVersion(CommentedConfig config) {
        if (config == null) {
            Logger.logCriticalError("Cannot parse version: config is null");
            configVersion = "unknown";
            return;
        }
        
        // Get version from config, fallback to "unknown" if not found
        String version = config.get("version");
        configVersion = version != null ? version : "unknown";
    }
    
    private void parseSettings(CommentedConfig config) {
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
                settings.setExcludedFileExtensions(new HashSet<>(excludedExtensions));
            }
            
            // Parse enabled tools
            List<String> enabledTools = settingsConfig.get("enabled_tools");
            if (enabledTools != null) {
                Set<ToolType> enabledToolsSet = new HashSet<>();
                for (String toolName : enabledTools) {
                    try {
                        enabledToolsSet.add(ToolType.valueOf(toolName.toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        Logger.logCriticalError("Invalid tool type: " + toolName);
                    }
                }
                settings.setEnabledTools(enabledToolsSet);
            }
        }
    }
    
    private void parsePatterns(CommentedConfig config) {
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
        // Re-parse patterns to apply updated dynamic values from the config object
        if (fileConfig != null) {
            parsePatterns(fileConfig);
        }
    }
    
    public void saveConfig() {
        if (fileConfig == null) {
            Logger.logCritical("Cannot save config, fileConfig is null.");
            return;
        }
    
        try {
            // Create a new empty config to build the output, ensuring a clean structure.
            CommentedConfig newConfig = TomlFormat.instance().createConfig();
    
            // Set version
            newConfig.set("version", this.configVersion);
            newConfig.setComment("version", " AI Secrets Detector Configuration\n Version of this config file - should match extension version");
    
            // Set settings, reading values from the current Config instance
            CommentedConfig settings = newConfig.createSubConfig();
            settings.set("workers", this.settings.getWorkers());
            settings.set("in_scope_only", this.settings.isInScopeOnly());
            settings.set("logging_enabled", this.settings.isLoggingEnabled());
            settings.set("randomness_algorithm_enabled", this.settings.isRandomnessAlgorithmEnabled());
            settings.set("generic_secret_min_length", this.settings.getGenericSecretMinLength());
            settings.set("generic_secret_max_length", this.settings.getGenericSecretMaxLength());
            settings.set("duplicate_threshold", this.settings.getDuplicateThreshold());
            settings.set("max_highlights_per_secret", this.settings.getMaxHighlightsPerSecret());
            settings.set("excluded_file_extensions", new ArrayList<>(this.settings.getExcludedFileExtensions()));
            
            List<String> enabledToolsStr = this.settings.getEnabledTools().stream()
                .map(ToolType::name).sorted().collect(Collectors.toList());
            settings.set("enabled_tools", enabledToolsStr);
            newConfig.set("settings", settings);
    
            // Set patterns
            List<CommentedConfig> patternsList = new ArrayList<>();
            if (patterns != null) {
                for (PatternConfig pattern : patterns) {
                    CommentedConfig patternMap = TomlFormat.newConcurrentConfig();
                    patternMap.set("name", pattern.getName());
                    patternMap.set("prefix", pattern.getPrefix());
                    patternMap.set("pattern", pattern.getPattern());
                    patternMap.set("suffix", pattern.getSuffix());
                    patternsList.add(patternMap);
                }
            }
            newConfig.set("patterns", patternsList);
    
            // Replace the content of the existing fileConfig with the new, clean config.
            fileConfig.clear();
            fileConfig.putAll(newConfig);
    
            // Save the file using our custom writer to preserve formatting
            createConfiguredTomlWriter().write(fileConfig, fileConfig.getFile(), WritingMode.REPLACE);
            
            Logger.logMsg("Configuration saved to " + fileConfig.getNioPath());
            
            // Notify of config change
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to save configuration: " + e.getMessage());
        }
    }
    
    /**
     * Resets the configuration file to the default state by overwriting it.
     */
    public void resetToDefaults() {
        try {
            String configFilePath = getDefaultConfigFilePath();
            Path configPath = Paths.get(configFilePath);
            
            try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
                if (defaultConfigStream == null) {
                    throw new IOException("Default config resource not found.");
                }
                Files.copy(defaultConfigStream, configPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            
            // Reload the configuration from the newly reset file
            loadConfig();
            
            Logger.logCritical("Configuration has been reset to defaults.");
            
            // Notify listeners about the change
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
            
        } catch (Exception e) {
            Logger.logCriticalError("Failed to reset configuration to defaults: " + e.getMessage());
        }
    }

    /**
     * This method is deprecated. Use resetToDefaults() instead.
     * @deprecated
     */
    @Deprecated
    public void resetToDefaultsComplete() {
        resetToDefaults();
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
        if (fileConfig == null) {
            throw new IOException("Configuration is not loaded, cannot export.");
        }
        Path destination = Paths.get(filePath);
        Files.createDirectories(destination.getParent());
        Files.copy(fileConfig.getNioPath(), destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
    
    /**
     * Import configuration from a TOML file
     * @param filePath The path to the config file to import
     * @throws IOException If file operations fail
     */
    public void importConfigFromFile(String filePath) throws IOException {
        Path sourcePath = Paths.get(filePath);
        if (!Files.exists(sourcePath)) {
            throw new IOException("Config file not found: " + filePath);
        }
        
        String configFilePath = getDefaultConfigFilePath();
        Path destinationPath = Paths.get(configFilePath);
        
        Files.createDirectories(destinationPath.getParent());
        Files.copy(sourcePath, destinationPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        
        // Reload config from the newly imported file
        loadConfig();
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
            configDir = Paths.get(userHome, ".config", "burp-ai-secrets-detector").toString();
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
     * Creates a TomlWriter configured to use triple-quotes for all strings.
     * This ensures regex patterns are preserved as raw literals without unwanted escaping.
     */
    private TomlWriter createConfiguredTomlWriter() {
        TomlWriter writer = new TomlWriter();
        writer.setIndent("  "); // Use 2-space indent for readability
        
        // Force all strings to be written as multi-line literal strings (''')
        // This ensures all values are preserved exactly as-is.
        writer.setWriteStringMultilinePredicate(str -> true);
        writer.setWriteStringLiteralPredicate(str -> true);
        
        return writer;
    }
} 