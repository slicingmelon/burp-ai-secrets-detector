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
import com.fasterxml.jackson.dataformat.toml.TomlMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.File;
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
    private JsonNode config;
    private List<PatternConfig> patterns;
    private Settings settings;
    private String configVersion; // Version of the current config
    private Runnable onConfigChangedCallback;
    private static final TomlMapper tomlMapper = new TomlMapper();
    
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
        this.config = tomlMapper.createObjectNode(); // Always initialize config to prevent null
        
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
            minimalConfig.config = tomlMapper.createObjectNode();
            minimalConfig.api = null;
            minimalConfig.onConfigChangedCallback = null;
            return minimalConfig;
        } catch (Exception e) {
            // If even minimal creation fails, create an absolutely basic instance
            Config emergency = new Config();
            emergency.patterns = new ArrayList<>();
            emergency.settings = new Settings();
            emergency.config = tomlMapper.createObjectNode();
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
                this.config = tomlMapper.readTree(savedConfig);
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
            this.config = tomlMapper.createObjectNode();
        }
    }
    
    private void loadDefaultConfig() {
        try {
            InputStream configStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH);
            if (configStream != null) {
                this.config = tomlMapper.readTree(configStream);
                parseConfig();
                // Save default config to persistence
                saveConfig();
            } else {
                Logger.logCriticalError("Default config file not found in resources");
                // Create empty config to avoid null pointer exceptions
                this.config = tomlMapper.createObjectNode();
            }
        } catch (Exception e) {
            Logger.logCriticalError("Failed to load default configuration: " + e.getMessage());
            // Create empty config to avoid null pointer exceptions
            this.config = tomlMapper.createObjectNode();
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
        JsonNode versionNode = config.get("version");
        configVersion = versionNode != null ? versionNode.asText("unknown") : "unknown";
    }
    
    private void parseSettings() {
        if (config == null) {
            Logger.logCriticalError("Cannot parse settings: config is null");
            return;
        }
        
        JsonNode settingsNode = config.get("settings");
        if (settingsNode != null && settingsNode.isObject()) {
            
            JsonNode workersNode = settingsNode.get("workers");
            if (workersNode != null && workersNode.isNumber()) {
                settings.setWorkers(workersNode.asInt());
            }
            
            JsonNode inScopeOnlyNode = settingsNode.get("in_scope_only");
            if (inScopeOnlyNode != null && inScopeOnlyNode.isBoolean()) {
                settings.setInScopeOnly(inScopeOnlyNode.asBoolean());
            }
            
            JsonNode loggingEnabledNode = settingsNode.get("logging_enabled");
            if (loggingEnabledNode != null && loggingEnabledNode.isBoolean()) {
                settings.setLoggingEnabled(loggingEnabledNode.asBoolean());
            }
            
            JsonNode randomnessAlgorithmEnabledNode = settingsNode.get("randomness_algorithm_enabled");
            if (randomnessAlgorithmEnabledNode != null && randomnessAlgorithmEnabledNode.isBoolean()) {
                settings.setRandomnessAlgorithmEnabled(randomnessAlgorithmEnabledNode.asBoolean());
            }
            
            JsonNode genericSecretMinLengthNode = settingsNode.get("generic_secret_min_length");
            if (genericSecretMinLengthNode != null && genericSecretMinLengthNode.isNumber()) {
                settings.setGenericSecretMinLength(genericSecretMinLengthNode.asInt());
            }
            
            JsonNode genericSecretMaxLengthNode = settingsNode.get("generic_secret_max_length");
            if (genericSecretMaxLengthNode != null && genericSecretMaxLengthNode.isNumber()) {
                settings.setGenericSecretMaxLength(genericSecretMaxLengthNode.asInt());
            }
            
            JsonNode duplicateThresholdNode = settingsNode.get("duplicate_threshold");
            if (duplicateThresholdNode != null && duplicateThresholdNode.isNumber()) {
                settings.setDuplicateThreshold(duplicateThresholdNode.asInt());
            }
            
            JsonNode maxHighlightsPerSecretNode = settingsNode.get("max_highlights_per_secret");
            if (maxHighlightsPerSecretNode != null && maxHighlightsPerSecretNode.isNumber()) {
                settings.setMaxHighlightsPerSecret(maxHighlightsPerSecretNode.asInt());
            }
            
            // Parse excluded file extensions
            JsonNode excludedExtensionsNode = settingsNode.get("excluded_file_extensions");
            if (excludedExtensionsNode != null && excludedExtensionsNode.isArray()) {
                Set<String> excludedExtensions = new HashSet<>();
                for (JsonNode extensionNode : excludedExtensionsNode) {
                    excludedExtensions.add(extensionNode.asText());
                }
                settings.setExcludedFileExtensions(excludedExtensions);
            }
            
            // Parse enabled tools
            JsonNode enabledToolsNode = settingsNode.get("enabled_tools");
            if (enabledToolsNode != null && enabledToolsNode.isArray()) {
                Set<ToolType> enabledTools = new HashSet<>();
                for (JsonNode toolNode : enabledToolsNode) {
                    try {
                        enabledTools.add(ToolType.valueOf(toolNode.asText()));
                    } catch (IllegalArgumentException e) {
                        Logger.logCriticalError("Invalid tool type: " + toolNode.asText());
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
        
        JsonNode patternsNode = config.get("patterns");
        if (patternsNode != null && patternsNode.isArray()) {
            for (JsonNode patternNode : patternsNode) {
                JsonNode nameNode = patternNode.get("name");
                JsonNode prefixNode = patternNode.get("prefix");
                JsonNode patternValueNode = patternNode.get("pattern");
                JsonNode suffixNode = patternNode.get("suffix");
                
                String name = nameNode != null ? nameNode.asText() : null;
                String prefix = prefixNode != null ? prefixNode.asText() : null;
                String pattern = patternValueNode != null ? patternValueNode.asText() : null;
                String suffix = suffixNode != null ? suffixNode.asText() : null;
                
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
            
            // Don't save if we're still initializing (this.config might be null)
            if (this.config == null) {
                Logger.logCriticalError("Cannot save config: config object is null (still initializing?)");
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
            String tomlString = tomlMapper.writeValueAsString(configMap);
            
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
     * Uses template-based approach to preserve original TOML formatting
     * @param tomlString The TOML content to write (not used in template approach)
     */
    private void autoSyncExternalConfigFile(String tomlString) {
        try {
            String configFilePath = getDefaultConfigFilePath();
            Path configPath = Paths.get(configFilePath);
            
            // Create directory if it doesn't exist
            Files.createDirectories(configPath.getParent());
            
            // Use template-based approach to preserve formatting
            syncConfigWithTemplate(configFilePath);
            
            Logger.logMsg("Auto-synced configuration to " + configFilePath);
            
        } catch (Exception e) {
            Logger.logErrorMsg("Failed to auto-sync config file: " + e.getMessage());
        }
    }
    
    /**
     * Sync external config file using template-based approach
     * Only updates [settings] section, preserves patterns formatting
     * @param configFilePath The path to write the config file
     */
    private void syncConfigWithTemplate(String configFilePath) throws IOException {
        // Read the original default config template
        InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH);
        if (defaultConfigStream == null) {
            throw new IOException("Default config template not found");
        }
        
        try {
            // Read template as string
            String templateContent = new String(defaultConfigStream.readAllBytes());
            
            // Update version and settings section
            String updatedContent = updateTemplateWithCurrentSettings(templateContent);
            
            // Write to file
            Files.write(Paths.get(configFilePath), updatedContent.getBytes());
            
        } finally {
            defaultConfigStream.close();
        }
    }
    
    /**
     * Update template content with current settings while preserving patterns
     * @param templateContent The original template content
     * @return Updated content with current settings
     */
    private String updateTemplateWithCurrentSettings(String templateContent) {
        StringBuilder updatedContent = new StringBuilder();
        String[] lines = templateContent.split("\n");
        boolean inSettingsSection = false;
        boolean foundVersion = false;
        
        for (String line : lines) {
            String trimmedLine = line.trim();
            
            // Update version line
            if (!foundVersion && trimmedLine.startsWith("version = ")) {
                updatedContent.append("version = \"").append(getCurrentExtensionVersion()).append("\"\n");
                foundVersion = true;
                continue;
            }
            
            // Detect [settings] section
            if (trimmedLine.equals("[settings]")) {
                inSettingsSection = true;
                updatedContent.append(line).append("\n");
                
                // Write current settings
                appendCurrentSettings(updatedContent);
                continue;
            }
            
            // End of settings section (next section starts)
            if (inSettingsSection && trimmedLine.startsWith("[") && !trimmedLine.equals("[settings]")) {
                inSettingsSection = false;
            }
            
            // Skip original settings lines, keep everything else
            if (!inSettingsSection) {
                updatedContent.append(line).append("\n");
            }
        }
        
        return updatedContent.toString();
    }
    
    /**
     * Append current settings to the content builder
     * @param content The content builder to append to
     */
    private void appendCurrentSettings(StringBuilder content) {
        if (settings == null) return;
        
        // Format settings exactly as we want them
        content.append("excluded_file_extensions = [");
        boolean first = true;
        for (String ext : settings.getExcludedFileExtensions()) {
            if (!first) content.append(", ");
            content.append("\"").append(ext).append("\"");
            first = false;
        }
        content.append("]\n");
        
        content.append("workers = ").append(settings.getWorkers()).append("\n");
        content.append("in_scope_only = ").append(settings.isInScopeOnly()).append("\n");
        content.append("logging_enabled = ").append(settings.isLoggingEnabled()).append("\n");
        content.append("randomness_algorithm_enabled = ").append(settings.isRandomnessAlgorithmEnabled()).append("\n");
        content.append("generic_secret_min_length = ").append(settings.getGenericSecretMinLength()).append("\n");
        content.append("generic_secret_max_length = ").append(settings.getGenericSecretMaxLength()).append("\n");
        content.append("duplicate_threshold = ").append(settings.getDuplicateThreshold()).append("\n");
        content.append("max_highlights_per_secret = ").append(settings.getMaxHighlightsPerSecret()).append("\n");
        
        content.append("enabled_tools = [");
        first = true;
        for (ToolType tool : settings.getEnabledTools()) {
            if (!first) content.append(", ");
            content.append("\"").append(tool.name()).append("\"");
            first = false;
        }
        content.append("]\n");
        content.append("\n"); // Add blank line before patterns
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
     * Uses template-based approach to preserve original formatting
     * @param filePath The path where to save the config file
     * @throws IOException If file operations fail
     */
    public void exportConfigToFile(String filePath) throws IOException {
        // Use template-based approach to preserve formatting
        syncConfigWithTemplate(filePath);
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
            this.config = tomlMapper.readTree(fileReader);
            
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
     * Creates config.toml using template approach only if it doesn't exist
     */
    public void initializeExternalConfigFile() {
        String configFilePath = getDefaultConfigFilePath();
        
        // Only create if config.toml doesn't exist (first install)
        if (!Files.exists(Paths.get(configFilePath))) {
            try {
                // Use template approach to create initial config file
                syncConfigWithTemplate(configFilePath);
                Logger.logCritical("First install: Created config file at " + configFilePath);
            } catch (IOException e) {
                Logger.logCriticalError("Failed to create initial config file: " + e.getMessage());
            }
        }
    }
    

    
} 