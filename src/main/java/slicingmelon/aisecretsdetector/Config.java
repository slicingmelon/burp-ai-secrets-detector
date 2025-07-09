/**
 * AI Secrets Detector
 * <p>
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Configuration management using TOML format
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.toml.TomlFactory;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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
    private static final String PERSISTENCE_CONFIG_KEY = "ai_secrets_detector_config";
    private static final String PERSISTENCE_VERSION_KEY = "ai_secrets_detector_version";

    private MontoyaApi api;
    private static Config instance;

    private String configVersion; // Version of the current config
    private Runnable onConfigChangedCallback;
    private Settings settings;
    private List<PatternConfig> patterns;

    private final TomlMapper tomlMapper;

    // Root class for TOML structure
    public static class TomlRoot {
        @JsonProperty("version")
        public String version;
        @JsonProperty("settings")
        public Settings settings;
        @JsonProperty("patterns")
        public List<PatternConfig> patterns;
    }

    // Configuration classes
    public static class PatternConfig {
        @JsonProperty("name")
        private String name;
        @JsonProperty("prefix")
        private String prefix;
        @JsonProperty("pattern")
        private String pattern;
        @JsonProperty("suffix")
        private String suffix;
        
        @JsonIgnore
        private Pattern compiledPattern;

        public PatternConfig() {}

        public PatternConfig(String name, String prefix, String pattern, String suffix) {
            this.name = name;
            this.prefix = prefix;
            this.pattern = pattern;
            this.suffix = suffix;
            // Don't compile here - will be compiled later with proper config values
        }

        public void compile() {
            compile(15, 80); // Default values if called without parameters
        }
        
        public void compile(int minLength, int maxLength) {
            String fullPattern = buildFullPattern(prefix, pattern, suffix, minLength, maxLength);
            try {
                Logger.logCritical("Compiling pattern '" + name + "' with regex: " + fullPattern);
                this.compiledPattern = Pattern.compile(fullPattern);
                Logger.logCritical("Successfully compiled pattern '" + name + "'");
            } catch (Exception e) {
                Logger.logCriticalError("FAILED to compile pattern '" + name + "' with regex: " + fullPattern + " - Error: " + e.getMessage());
                throw new IllegalArgumentException("Invalid regex in pattern '" + name + "': " + e.getMessage(), e);
            }
        }

        private String buildFullPattern(String prefix, String pattern, String suffix, int minLength, int maxLength) {
            StringBuilder fullPattern = new StringBuilder();
            if (prefix != null && !prefix.isEmpty()) {
                fullPattern.append(replacePlaceholders(prefix, minLength, maxLength));
            }
            if (pattern != null && !pattern.isEmpty()) {
                fullPattern.append(replacePlaceholders(pattern, minLength, maxLength));
            }
            if (suffix != null && !suffix.isEmpty()) {
                fullPattern.append(replacePlaceholders(suffix, minLength, maxLength));
            }
            return fullPattern.toString();
        }
        
        /**
         * Replace placeholders in regex patterns with actual config values
         * Performs strict exact replacement to avoid messing up the regex
         */
        private String replacePlaceholders(String text, int minLength, int maxLength) {
            if (text == null) return text;
            
            // Replace generic_secret_min_length and generic_secret_max_length with actual values
            // Use exact string replacement to be super strict
            String result = text.replace("generic_secret_min_length", String.valueOf(minLength));
            result = result.replace("generic_secret_max_length", String.valueOf(maxLength));
            
            return result;
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

        public void setName(String name) {
            this.name = name;
        }

        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public void setSuffix(String suffix) {
            this.suffix = suffix;
        }
    }

    public static class Settings {
        @JsonProperty("workers")
        private int workers;
        @JsonProperty("in_scope_only")
        private boolean inScopeOnly;
        @JsonProperty("logging_enabled")
        private boolean loggingEnabled;
        @JsonProperty("randomness_algorithm_enabled")
        private boolean randomnessAlgorithmEnabled;
        @JsonProperty("generic_secret_min_length")
        private int genericSecretMinLength;
        @JsonProperty("generic_secret_max_length")
        private int genericSecretMaxLength;
        @JsonProperty("duplicate_threshold")
        private int duplicateThreshold;
        @JsonProperty("max_highlights_per_secret")
        private int maxHighlightsPerSecret;
        @JsonProperty("excluded_file_extensions")
        private Set<String> excludedFileExtensions;
        @JsonProperty("enabled_tools")
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
        this.tomlMapper = createTomlMapper();
        loadConfig();
    }

    private TomlMapper createTomlMapper() {
        return TomlMapper.builder()
                .build();
    }

    public static Config getInstance() {
        if (instance == null) {
            // This is a fallback for cases where getInstance is called before initialization
            instance = createMinimalInstance();
        }
        return instance;
    }

    public static Config initialize(MontoyaApi api, Runnable onConfigChangedCallback) {
        if (instance == null) {
            instance = new Config(api, onConfigChangedCallback);
        } else {
            // If already initialized, update the api and callback
            instance.api = api;
            instance.onConfigChangedCallback = onConfigChangedCallback;
        }
        return instance;
    }

    /**
     * Creates a minimal instance of Config without loading from a file.
     * This is used as a fallback.
     */
    private static Config createMinimalInstance() {
        // A special constructor for creating a minimal, non-api-linked instance.
        return new Config();
    }

    /**
     * Private constructor for minimal instance
     */
    private Config() {
        this.api = null;
        this.onConfigChangedCallback = null;
        this.patterns = new CopyOnWriteArrayList<>();
        this.settings = new Settings();
        this.tomlMapper = createTomlMapper();
        loadDefaultConfig();
    }

    private void loadConfig() {
        
        // 1. Try to load from Burp persistence first (primary source of truth)
        if (api != null && loadFromBurpPersistence()) {
            saveToConfigFile();
            return;
        }

        // 2. If not available, try to load from external config.toml
        Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
        if (Files.exists(configPath)) {
            try {
                TomlRoot tomlRoot = tomlMapper.readValue(configPath.toFile(), TomlRoot.class);
                parseTomlRoot(tomlRoot);
                saveToBurpPersistence(); // Save to Burp persistence for future use
                return;
            } catch (IOException e) {
                Logger.logCriticalError("Error loading config from file: " + e.getMessage());
            }
        }

        // 3. If neither available, load defaults and save to both
        loadDefaultConfig();
        saveToBurpPersistence();
        saveToConfigFile();
    }

    private boolean loadFromBurpPersistence() {
        if (api == null) {
            return false;
        }

        try {
            String configData = api.persistence().extensionData().getString(PERSISTENCE_CONFIG_KEY);
            String versionData = api.persistence().extensionData().getString(PERSISTENCE_VERSION_KEY);
            
            if (configData != null && !configData.isEmpty()) {
                TomlRoot tomlRoot = tomlMapper.readValue(configData, TomlRoot.class);
                parseTomlRoot(tomlRoot);
                
                // Use persisted version if available, otherwise use the version from the config
                if (versionData != null && !versionData.isEmpty()) {
                    this.configVersion = versionData;
                }
                
                return true;
            }
        } catch (Exception e) {
            Logger.logCriticalError("Error loading config from Burp persistence: " + e.getMessage());
        }
        return false;
    }

    private void saveToBurpPersistence() {
        if (api == null) {
            return;
        }

        try {
            TomlRoot tomlRoot = new TomlRoot();
            tomlRoot.version = this.configVersion;
            tomlRoot.settings = this.settings;
            tomlRoot.patterns = this.patterns;

            String configData = tomlMapper.writeValueAsString(tomlRoot);
            api.persistence().extensionData().setString(PERSISTENCE_CONFIG_KEY, configData);
            api.persistence().extensionData().setString(PERSISTENCE_VERSION_KEY, this.configVersion);
        } catch (Exception e) {
            Logger.logCriticalError("Error saving config to Burp persistence: " + e.getMessage());
        }
    }

    private void loadDefaultConfig() {
        try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
            if (defaultConfigStream != null) {
                TomlRoot tomlRoot = tomlMapper.readValue(defaultConfigStream, TomlRoot.class);
                parseTomlRoot(tomlRoot);
            } else {
                Logger.logCriticalError("Default config file not found.");
            }
        } catch (IOException e) {
            Logger.logCriticalError("Error loading default config: " + e.getMessage());
        }
    }

    private void parseTomlRoot(TomlRoot tomlRoot) {
        if (tomlRoot != null) {
            this.configVersion = tomlRoot.version;
            this.settings = tomlRoot.settings != null ? tomlRoot.settings : new Settings();
            this.patterns = tomlRoot.patterns != null ? new CopyOnWriteArrayList<>(tomlRoot.patterns) : new CopyOnWriteArrayList<>();
            
            // Compile patterns with actual config values
            int minLength = this.settings.getGenericSecretMinLength();
            int maxLength = this.settings.getGenericSecretMaxLength();
            this.patterns.forEach(pattern -> pattern.compile(minLength, maxLength));
            
        }
    }
    
    public void saveConfig() {
        
        // Update version to current extension version
        this.configVersion = getCurrentExtensionVersion();
        
        // Recompile patterns with current config values
        recompilePatterns();
        
        // Save to Burp persistence (primary)
        saveToBurpPersistence();
        
        // Auto-save to config.toml file as well
        saveToConfigFile();
        
        // Notify callback
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
        
        // Notify UI to refresh if available
        if (AISecretsDetector.getInstance() != null) {
            UI ui = AISecretsDetector.getInstance().getUI();
            if (ui != null) {
                ui.refreshUI();
            }
        }
    }

    private void saveToConfigFile() {
        try {
            Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
            Logger.logCritical("Config.saveToConfigFile: Saving to path: " + configPath.toAbsolutePath());
            
            Files.createDirectories(configPath.getParent());

            // Always use the beautiful default format, then update values
            Logger.logCritical("Config.saveToConfigFile: Copying default config");
            copyDefaultConfigToUserDirectory(configPath);
            
            Logger.logCritical("Config.saveToConfigFile: Updating config values - minLength=" + settings.getGenericSecretMinLength() + ", maxLength=" + settings.getGenericSecretMaxLength());
            updateConfigValues(configPath);
            
            Logger.logCritical("Config.saveToConfigFile: Config file saved successfully");
            
        } catch (IOException e) {
            Logger.logCriticalError("Error saving config to file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Updates only the values in the config file, preserving formatting and structure
     * Also updates patterns to include any user-added patterns
     */
    private void updateConfigValues(Path configPath) throws IOException {
        List<String> lines = Files.readAllLines(configPath, StandardCharsets.UTF_8);
        List<String> updatedLines = new ArrayList<>();
        
        boolean inSettingsSection = false;
        boolean inPatternsSection = false;
        boolean foundPatternsSection = false;
        
        for (String line : lines) {
            String trimmed = line.trim();
            
            // Detect sections
            if (trimmed.equals("[settings]")) {
                inSettingsSection = true;
                inPatternsSection = false;
                updatedLines.add(line);
                continue;
            } else if (trimmed.startsWith("[[patterns]]")) {
                inSettingsSection = false;
                inPatternsSection = true;
                foundPatternsSection = true;
                break; // Stop processing here, we'll append our patterns
            } else if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                inSettingsSection = false;
                inPatternsSection = false;
                updatedLines.add(line);
                continue;
            }
            
            // Update version
            if (trimmed.startsWith("version = ")) {
                updatedLines.add("version = \"" + this.configVersion + "\"");
                continue;
            }
            
            // Update settings values
            if (inSettingsSection) {
                if (trimmed.startsWith("workers = ")) {
                    updatedLines.add("workers = " + this.settings.getWorkers());
                } else if (trimmed.startsWith("in_scope_only = ")) {
                    updatedLines.add("in_scope_only = " + this.settings.isInScopeOnly());
                } else if (trimmed.startsWith("logging_enabled = ")) {
                    updatedLines.add("logging_enabled = " + this.settings.isLoggingEnabled());
                } else if (trimmed.startsWith("randomness_algorithm_enabled = ")) {
                    updatedLines.add("randomness_algorithm_enabled = " + this.settings.isRandomnessAlgorithmEnabled());
                } else if (trimmed.startsWith("generic_secret_min_length = ")) {
                    updatedLines.add("generic_secret_min_length = " + this.settings.getGenericSecretMinLength());
                } else if (trimmed.startsWith("generic_secret_max_length = ")) {
                    updatedLines.add("generic_secret_max_length = " + this.settings.getGenericSecretMaxLength());
                } else if (trimmed.startsWith("duplicate_threshold = ")) {
                    updatedLines.add("duplicate_threshold = " + this.settings.getDuplicateThreshold());
                } else if (trimmed.startsWith("max_highlights_per_secret = ")) {
                    updatedLines.add("max_highlights_per_secret = " + this.settings.getMaxHighlightsPerSecret());
                } else if (trimmed.startsWith("excluded_file_extensions = ")) {
                    updatedLines.add("excluded_file_extensions = " + formatStringArray(this.settings.getExcludedFileExtensions()));
                } else if (trimmed.startsWith("enabled_tools = ")) {
                    updatedLines.add("enabled_tools = " + formatToolArray(this.settings.getEnabledTools()));
                } else {
                    updatedLines.add(line);
                }
            } else {
                updatedLines.add(line);
            }
        }
        
        // Append all current patterns (preserves user-added ones)
        if (foundPatternsSection) {
            updatedLines.add(""); // Empty line before patterns section
        }
        
        for (PatternConfig pattern : this.patterns) {
            updatedLines.add("[[patterns]]");
            updatedLines.add("name = \"" + pattern.getName() + "\"");
            updatedLines.add("prefix = '''" + pattern.getPrefix() + "'''");
            updatedLines.add("pattern = '''" + pattern.getPattern() + "'''");
            updatedLines.add("suffix = '''" + pattern.getSuffix() + "'''");
            updatedLines.add(""); // Empty line after each pattern
        }
        
        // Write the updated content back
        Files.write(configPath, updatedLines, StandardCharsets.UTF_8);
    }

    private String formatStringArray(Set<String> strings) {
        if (strings == null || strings.isEmpty()) {
            return "[]";
        }
        return "[" + strings.stream()
                .map(s -> "\"" + s + "\"")
                .collect(Collectors.joining(", ")) + "]";
    }

    private String formatToolArray(Set<ToolType> tools) {
        if (tools == null || tools.isEmpty()) {
            return "[]";
        }
        return "[" + tools.stream()
                .map(t -> "\"" + t.name() + "\"")
                .collect(Collectors.joining(", ")) + "]";
    }
    
    private void copyDefaultConfigToUserDirectory(Path configPath) throws IOException {
        try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
            if (defaultConfigStream != null) {
                Files.copy(defaultConfigStream, configPath, StandardCopyOption.REPLACE_EXISTING);
                Logger.logCritical("Copied default config to: " + configPath.toAbsolutePath());
            } else {
                Logger.logCriticalError("Default config resource not found: " + DEFAULT_CONFIG_PATH);
            }
        }
    }
    
    public void resetToDefaults() {
        loadDefaultConfig();
        saveConfig(); // This will save to both Burp persistence and config.toml
        
        // Notify UI to refresh if available
        if (AISecretsDetector.getInstance() != null) {
            UI ui = AISecretsDetector.getInstance().getUI();
            if (ui != null) {
                ui.refreshUI();
            }
        }
    }

    @Deprecated
    public void resetToDefaultsComplete() {
        // This method is deprecated and now just calls the simpler resetToDefaults.
        resetToDefaults();
    }
    
    public void updateAndMergeWithDefaults() {
        try {
            // Load the current default config
            TomlRoot defaultTomlRoot = null;
            try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
                if (defaultConfigStream != null) {
                    defaultTomlRoot = tomlMapper.readValue(defaultConfigStream, TomlRoot.class);
                }
            }

            if (defaultTomlRoot == null) {
                Logger.logCriticalError("Could not load default config for merging");
                return;
            }

            // Merge logic: keep user settings but add new default patterns
            String oldVersion = this.configVersion;
            Settings userSettings = this.settings;
            List<PatternConfig> userPatterns = new ArrayList<>(this.patterns);

            // Parse new defaults
            parseTomlRoot(defaultTomlRoot);

            // Restore user settings
            this.settings = userSettings;

            // Merge patterns: keep user patterns and add new default ones
            List<PatternConfig> newPatterns = new ArrayList<>(userPatterns);
            Set<String> userPatternNames = userPatterns.stream()
                    .map(PatternConfig::getName)
                    .collect(Collectors.toSet());

            // Add new default patterns that user doesn't have
            for (PatternConfig defaultPattern : defaultTomlRoot.patterns) {
                if (!userPatternNames.contains(defaultPattern.getName())) {
                    newPatterns.add(defaultPattern);
                }
            }

            this.patterns = new CopyOnWriteArrayList<>(newPatterns);
            
            // Compile patterns with actual config values
            int minLength = this.settings.getGenericSecretMinLength();
            int maxLength = this.settings.getGenericSecretMaxLength();
            this.patterns.forEach(pattern -> pattern.compile(minLength, maxLength));

            // Update version to current
            this.configVersion = getCurrentExtensionVersion();

            // Save the merged config
            saveConfig();

            Logger.logCritical("Config updated from version " + oldVersion + " to " + this.configVersion);
        } catch (Exception e) {
            Logger.logCriticalError("Error updating and merging config: " + e.getMessage());
        }
    }

    public void reloadConfig() {
        loadConfig();
    }

    public Settings getSettings() {
        if (settings == null) {
            return new Settings();
        }
        return settings;
    }

    public List<PatternConfig> getPatterns() {
        if (patterns == null) {
            return new ArrayList<>();
        }
        return new ArrayList<>(patterns); // Return a copy
    }

    public String getConfigVersion() {
        return configVersion;
    }

    public String getCurrentExtensionVersion() {
        return VersionUtil.getVersion();
    }

    public boolean isConfigUpToDate() {
        String currentVersion = getCurrentExtensionVersion();
        return currentVersion != null && currentVersion.equals(configVersion);
    }
    
    public boolean isConfigVersionNewer() {
        if (configVersion == null) {
            return false; // No config version, assume not newer
        }
        String currentVersion = getCurrentExtensionVersion();
        if (currentVersion == null) {
            return true; // No extension version, config is "newer"
        }
        return compareVersions(configVersion, currentVersion) > 0;
    }

    private int compareVersions(String version1, String version2) {
        if (version1 == null && version2 == null) return 0;
        if (version1 == null) return -1;
        if (version2 == null) return 1;
        
        String[] parts1 = version1.split("\\.");
        String[] parts2 = version2.split("\\.");
        int length = Math.max(parts1.length, parts2.length);
        
        for (int i = 0; i < length; i++) {
            int v1 = i < parts1.length ? Integer.parseInt(parts1[i]) : 0;
            int v2 = i < parts2.length ? Integer.parseInt(parts2[i]) : 0;
            if (v1 < v2) {
                return -1;
            }
            if (v1 > v2) {
                return 1;
            }
        }
        return 0;
    }

    public void updateGenericSecretLengths(int minLength, int maxLength) {
        Logger.logCritical("Config.updateGenericSecretLengths: Called with minLength=" + minLength + ", maxLength=" + maxLength);
        
        if (settings != null) {
            int oldMinLength = settings.getGenericSecretMinLength();
            int oldMaxLength = settings.getGenericSecretMaxLength();
            
            settings.setGenericSecretMinLength(minLength);
            settings.setGenericSecretMaxLength(maxLength);
            
            Logger.logCritical("Config.updateGenericSecretLengths: Updated settings from " + oldMinLength + "-" + oldMaxLength + " to " + minLength + "-" + maxLength);
            
            // Recompile all patterns with new length values
            recompilePatterns();
            
            Logger.logCritical("Config.updateGenericSecretLengths: Calling saveConfig()");
            saveConfig();
            
            Logger.logCritical("Config.updateGenericSecretLengths: saveConfig() completed");
        } else {
            Logger.logCriticalError("Config.updateGenericSecretLengths: settings is null!");
        }
    }
    
    /**
     * Recompile all patterns with current config values
     */
    private void recompilePatterns() {
        if (patterns != null && settings != null) {
            int minLength = settings.getGenericSecretMinLength();
            int maxLength = settings.getGenericSecretMaxLength();
            patterns.forEach(pattern -> pattern.compile(minLength, maxLength));
        }
    }
    
    public void exportConfigToFile(String filePath) throws IOException {
        Path destinationPath = Paths.get(filePath);
        Files.createDirectories(destinationPath.getParent());
        
        TomlRoot tomlRoot = new TomlRoot();
        tomlRoot.version = this.configVersion;
        tomlRoot.settings = this.settings;
        tomlRoot.patterns = this.patterns;
        
        tomlMapper.writeValue(destinationPath.toFile(), tomlRoot);
    }
    
    public void importConfigFromFile(String filePath) throws IOException {
        Path sourcePath = Paths.get(filePath);
        if (Files.exists(sourcePath)) {
            TomlRoot tomlRoot = tomlMapper.readValue(sourcePath.toFile(), TomlRoot.class);
            
            parseTomlRoot(tomlRoot);
            
            // Update version to current extension version
            this.configVersion = getCurrentExtensionVersion();
            
            // Save to Burp persistence (primary storage) but don't overwrite the config file
            saveToBurpPersistence();
            
            // Notify callback about config changes
            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
            
            // Notify UI to refresh if available
            if (AISecretsDetector.getInstance() != null) {
                UI ui = AISecretsDetector.getInstance().getUI();
                if (ui != null) {
                    ui.refreshUI();
                }
            }
        } else {
            throw new IOException("File not found: " + filePath);
        }
    }
    
    public String getDefaultConfigFilePath() {
        Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
        return configPath.toAbsolutePath().toString();
    }
    
    public boolean hasExportedConfigFile() {
        Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
        return Files.exists(configPath);
    }

    private TomlRoot loadFromConfigFile() {
        try {
            Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
            if (Files.exists(configPath)) {
                return tomlMapper.readValue(configPath.toFile(), TomlRoot.class);
            }
        } catch (IOException e) {
            Logger.logCriticalError("Error loading config from file: " + e.getMessage());
        }
        return null;
    }
} 