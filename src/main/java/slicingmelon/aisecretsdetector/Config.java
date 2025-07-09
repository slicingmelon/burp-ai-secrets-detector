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
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.toml.TomlFactory;
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
        private Pattern compiledPattern;

        public PatternConfig() {}

        public PatternConfig(String name, String prefix, String pattern, String suffix) {
            this.name = name;
            this.prefix = prefix;
            this.pattern = pattern;
            this.suffix = suffix;
            compile();
        }

        public void compile() {
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
        this.tomlMapper = TomlMapper.builder()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                .build();
        loadConfig();
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
        this.tomlMapper = TomlMapper.builder()
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                .build();
        loadDefaultConfig();
    }

    private void loadConfig() {
        try {
            Path configPath = Paths.get(System.getProperty("user.home"), ".burp-ai-secrets-detector", "config.toml");
            if (Files.exists(configPath)) {
                TomlRoot tomlRoot = tomlMapper.readValue(configPath.toFile(), TomlRoot.class);
                parseTomlRoot(tomlRoot);
            } else {
                loadDefaultConfig();
                saveConfig(); // Save the default config to the user's home directory
            }
        } catch (IOException e) {
            Logger.logCriticalError("Error loading config: " + e.getMessage());
            loadDefaultConfig();
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
            this.settings = tomlRoot.settings;
            this.patterns = new CopyOnWriteArrayList<>(tomlRoot.patterns);
            this.patterns.forEach(PatternConfig::compile);
        }
    }
    
    private void saveConfig() {
        try {
            Path configPath = Paths.get(System.getProperty("user.home"), ".burp-ai-secrets-detector", "config.toml");
            Files.createDirectories(configPath.getParent());

            TomlRoot tomlRoot = new TomlRoot();
            tomlRoot.version = getCurrentExtensionVersion();
            tomlRoot.settings = this.settings;
            tomlRoot.patterns = this.patterns;

            tomlMapper.writeValue(configPath.toFile(), tomlRoot);

            if (onConfigChangedCallback != null) {
                onConfigChangedCallback.run();
            }
        } catch (IOException e) {
            Logger.logCriticalError("Error saving config: " + e.getMessage());
        }
    }
    
    public void resetToDefaults() {
        loadDefaultConfig();
        saveConfig(); // Persist the default configuration
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
    }

    @Deprecated
    public void resetToDefaultsComplete() {
        // This method is deprecated and now just calls the simpler resetToDefaults.
        resetToDefaults();
    }
    
    public void updateAndMergeWithDefaults() {
        // Jackson handles this more cleanly by deserializing. This might not be needed.
        // For now, let's keep it simple and just reload the config.
        loadConfig();
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
        if (settings != null) {
            settings.setGenericSecretMinLength(minLength);
            settings.setGenericSecretMaxLength(maxLength);
            saveConfig();
        }
    }
    
    public void exportConfigToFile(String filePath) throws IOException {
        Path destinationPath = Paths.get(filePath);
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
            saveConfig();
        } else {
            throw new IOException("File not found: " + filePath);
        }
    }

    public String getDefaultConfigFilePath() {
        Path configPath = Paths.get(System.getProperty("user.home"), ".burp-ai-secrets-detector", "config.toml");
        if (Files.exists(configPath)) {
            return configPath.toString();
        } else {
            // If it doesn't exist, we can indicate that it will be created on next save.
            // Or return the path where it's expected to be.
            return configPath.toAbsolutePath().toString();
        }
    }
    
    public boolean hasExportedConfigFile() {
        Path configPath = Paths.get(System.getProperty("user.home"), ".burp-ai-secrets-detector", "config.toml");
        return Files.exists(configPath);
    }
} 