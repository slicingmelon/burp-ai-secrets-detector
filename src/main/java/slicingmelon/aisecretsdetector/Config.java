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
import com.fasterxml.jackson.dataformat.toml.TomlMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
//import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.concurrent.CopyOnWriteArrayList;
// import java.util.concurrent.CopyOnWriteArraySet;

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
    private List<ExclusionConfig> exclusions;

    private final TomlMapper tomlMapper;

    // Root class for TOML structure
    public static class TomlRoot {
        @JsonProperty("version")
        public String version;
        @JsonProperty("settings")
        public Settings settings;
        @JsonProperty("patterns")
        public List<PatternConfig> patterns;
        @JsonProperty("exclusions")
        public List<ExclusionConfig> exclusions;
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
        }

        public void compile() {
            compile(15, 80); // Default values if called without parameters
        }
        
        public void compile(int minLength, int maxLength) {
            String fullPattern = buildFullPattern(prefix, pattern, suffix, minLength, maxLength);
            try {
                //Logger.logCritical("Compiling pattern '" + name + "' with regex: " + fullPattern);
                this.compiledPattern = Pattern.compile(fullPattern);
                //Logger.logCritical("Successfully compiled pattern '" + name + "'");
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

    public static class ExclusionConfig {
        // URL patterns - single string or array
        @JsonProperty("url")
        private String url;
        @JsonProperty("urls")
        private List<String> urls;
        
        // Context patterns - single string or array  
        @JsonProperty("context")
        private String context;
        @JsonProperty("contexts")
        private List<String> contexts;
        
        @JsonIgnore
        private List<Pattern> compiledUrlPatterns;
        @JsonIgnore
        private List<Pattern> compiledContextPatterns;

        public ExclusionConfig() {
            this.urls = new ArrayList<>();
            this.contexts = new ArrayList<>();
        }

        public ExclusionConfig(String url, String context) {
            this();
            this.url = url;
            this.context = context;
            compile();
        }

        public ExclusionConfig(List<String> urls, List<String> contexts) {
            this();
            this.urls = urls != null ? new ArrayList<>(urls) : new ArrayList<>();
            this.contexts = contexts != null ? new ArrayList<>(contexts) : new ArrayList<>();
            compile();
        }

        public void compile() {
            compiledUrlPatterns = new ArrayList<>();
            compiledContextPatterns = new ArrayList<>();
            
            // Compile URL patterns
            List<String> allUrls = getAllUrls();
            for (String urlPattern : allUrls) {
                try {
                    compiledUrlPatterns.add(Pattern.compile(urlPattern));
                } catch (Exception e) {
                    Logger.logCriticalError("FAILED to compile URL exclusion regex: " + urlPattern + " - Error: " + e.getMessage());
                    throw new IllegalArgumentException("Invalid URL regex in exclusion: " + e.getMessage(), e);
                }
            }
            
            // Compile Context patterns
            List<String> allContexts = getAllContexts();
            for (String contextPattern : allContexts) {
                try {
                    compiledContextPatterns.add(Pattern.compile(contextPattern));
                } catch (Exception e) {
                    Logger.logCriticalError("FAILED to compile Context exclusion regex: " + contextPattern + " - Error: " + e.getMessage());
                    throw new IllegalArgumentException("Invalid Context regex in exclusion: " + e.getMessage(), e);
                }
            }
        }

        // Get all URL patterns (single + array)
        public List<String> getAllUrls() {
            List<String> allUrls = new ArrayList<>();
            if (url != null && !url.trim().isEmpty()) {
                allUrls.add(url);
            }
            if (urls != null) {
                allUrls.addAll(urls);
            }
            return allUrls;
        }

        // Get all context patterns (single + array)
        public List<String> getAllContexts() {
            List<String> allContexts = new ArrayList<>();
            if (context != null && !context.trim().isEmpty()) {
                allContexts.add(context);
            }
            if (contexts != null) {
                allContexts.addAll(contexts);
            }
            return allContexts;
        }

        /**
         * Check if this exclusion matches the given URL and context
         * Logic: URL AND Context (both must match if both are specified)
         */
        public boolean matches(String targetUrl, String targetContext) {
            boolean urlMatches = matchesUrl(targetUrl);
            boolean contextMatches = matchesContext(targetContext);
            
            // If both URL and Context are specified, both must match (AND)
            List<String> allUrls = getAllUrls();
            List<String> allContexts = getAllContexts();
            
            if (!allUrls.isEmpty() && !allContexts.isEmpty()) {
                return urlMatches && contextMatches;
            }
            // If only URL is specified
            else if (!allUrls.isEmpty()) {
                return urlMatches;
            }
            // If only Context is specified
            else if (!allContexts.isEmpty()) {
                return contextMatches;
            }
            
            return false;
        }

        private boolean matchesUrl(String targetUrl) {
            if (targetUrl == null || compiledUrlPatterns.isEmpty()) {
                return compiledUrlPatterns.isEmpty(); // No URL patterns = match all URLs
            }
            
            for (Pattern pattern : compiledUrlPatterns) {
                if (pattern.matcher(targetUrl).find()) {
                    return true;
                }
            }
            return false;
        }

        private boolean matchesContext(String targetContext) {
            if (targetContext == null || compiledContextPatterns.isEmpty()) {
                return compiledContextPatterns.isEmpty(); // No context patterns = match all contexts
            }
            
            for (Pattern pattern : compiledContextPatterns) {
                if (pattern.matcher(targetContext).find()) {
                    return true;
                }
            }
            return false;
        }

        // Getters and setters
        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls = urls;
        }

        public String getContext() {
            return context;
        }

        public void setContext(String context) {
            this.context = context;
        }

        public List<String> getContexts() {
            return contexts;
        }

        public void setContexts(List<String> contexts) {
            this.contexts = contexts;
        }

        public List<Pattern> getCompiledUrlPatterns() {
            return compiledUrlPatterns;
        }

        public List<Pattern> getCompiledContextPatterns() {
            return compiledContextPatterns;
        }

        // Backward compatibility methods
        @Deprecated
        public String getType() {
            return "context"; // Legacy compatibility
        }

        @Deprecated
        public String getRegex() {
            return context; // Legacy compatibility
        }

        @Deprecated
        public String getPatternName() {
            return "*"; // Legacy compatibility
        }

        @Deprecated
        public boolean matchesPattern(String patternName) {
            return true; // New design applies to all patterns
        }

        @Deprecated
        public boolean matches(String input) {
            return matchesContext(input); // Legacy compatibility
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
        @JsonProperty("excluded_mime_types")
        private Set<String> excludedMimeTypes;
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
            this.excludedMimeTypes = new HashSet<>();
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

        public Set<String> getExcludedMimeTypes() {
            return excludedMimeTypes;
        }

        public void setExcludedMimeTypes(Set<String> excludedMimeTypes) {
            this.excludedMimeTypes = excludedMimeTypes;
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
                .enable(com.fasterxml.jackson.databind.MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
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
            // Success - Burp persistence is the single source of truth
            return;
        }

        // 2. If not available, load defaults and save to Burp persistence
        loadDefaultConfig();
        if (api != null) {
            saveToBurpPersistence();
        }
    }


    private boolean loadFromBurpPersistence() {
        if (api == null) {
            return false;
        }

        try {
            String configData = api.persistence().extensionData().getString(PERSISTENCE_CONFIG_KEY);
            String versionData = api.persistence().extensionData().getString(PERSISTENCE_VERSION_KEY);
            
            if (configData != null && !configData.isEmpty()) {
                // Parse the TOML content using Jackson
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
            Logger.logCriticalError("This is likely due to corrupted config from a previous version.");
            Logger.logCriticalError("Clearing corrupted config and falling back to defaults...");
            
            // Clear the corrupted config from persistence
            try {
                api.persistence().extensionData().deleteString(PERSISTENCE_CONFIG_KEY);
                api.persistence().extensionData().deleteString(PERSISTENCE_VERSION_KEY);
                Logger.logCritical("Corrupted config cleared from Burp persistence.");
            } catch (Exception clearError) {
                Logger.logCriticalError("Failed to clear corrupted config: " + clearError.getMessage());
            }
        }
        return false;
    }

    private void saveToBurpPersistence() {
        if (api == null) {
            return;
        }

        try {
            // Use Night-Config writer for beautiful TOML with triple quotes
            String configData = TomlWriter.writeToString(this);
            
            // Save to Burp persistence (single source of truth)
            api.persistence().extensionData().setString(PERSISTENCE_CONFIG_KEY, configData);
            api.persistence().extensionData().setString(PERSISTENCE_VERSION_KEY, this.configVersion);
            
            Logger.logCritical("Configuration saved to Burp persistence");
        } catch (Exception e) {
            Logger.logCriticalError("Error saving config to Burp persistence: " + e.getMessage());
        }
    }

    private void loadDefaultConfig() {
        try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
            if (defaultConfigStream != null) {
                // Read and parse TOML content using Jackson
                byte[] rawBytes = defaultConfigStream.readAllBytes();
                String tomlContent = new String(rawBytes, StandardCharsets.UTF_8);
                
                TomlRoot tomlRoot = tomlMapper.readValue(tomlContent, TomlRoot.class);
                parseTomlRoot(tomlRoot);
            } else {
                Logger.logCriticalError("Default config file not found.");
            }
        } catch (IOException e) {
            Logger.logCriticalError("Error loading default config: " + e.getMessage());
        }
    }

    /**
     * Get default excluded file extensions from the default config file
     */
    private Set<String> getDefaultExcludedFileExtensions() {
        try {
            TomlRoot defaultConfig = loadDefaultTomlRoot();
            if (defaultConfig != null && defaultConfig.settings != null && defaultConfig.settings.getExcludedFileExtensions() != null) {
                return new HashSet<>(defaultConfig.settings.getExcludedFileExtensions());
            }
        } catch (Exception e) {
            Logger.logCriticalError("Error reading default excluded file extensions: " + e.getMessage());
        }
        return new HashSet<>(); // Fallback to empty set
    }

    /**
     * Get default excluded MIME types from the default config file
     */
    private Set<String> getDefaultExcludedMimeTypes() {
        try {
            TomlRoot defaultConfig = loadDefaultTomlRoot();
            if (defaultConfig != null && defaultConfig.settings != null && defaultConfig.settings.getExcludedMimeTypes() != null) {
                return new HashSet<>(defaultConfig.settings.getExcludedMimeTypes());
            }
        } catch (Exception e) {
            Logger.logCriticalError("Error reading default excluded MIME types: " + e.getMessage());
        }
        return new HashSet<>(); // Fallback to empty set
    }

    /**
     * Load and parse the default TOML configuration without affecting current state
     */
    private TomlRoot loadDefaultTomlRoot() {
        try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
            if (defaultConfigStream != null) {
                byte[] rawBytes = defaultConfigStream.readAllBytes();
                String defaultRawToml = new String(rawBytes, StandardCharsets.UTF_8);
                return tomlMapper.readValue(defaultRawToml, TomlRoot.class);
            }
        } catch (Exception e) {
            Logger.logCriticalError("Error loading default TOML root: " + e.getMessage());
        }
        return null;
    }

    private void parseTomlRoot(TomlRoot tomlRoot) {
        if (tomlRoot != null) {
            this.configVersion = tomlRoot.version;
            this.settings = tomlRoot.settings != null ? tomlRoot.settings : new Settings();
            this.patterns = tomlRoot.patterns != null ? new CopyOnWriteArrayList<>(tomlRoot.patterns) : new CopyOnWriteArrayList<>();
            this.exclusions = tomlRoot.exclusions != null ? new CopyOnWriteArrayList<>(tomlRoot.exclusions) : new CopyOnWriteArrayList<>();
            Logger.logCritical("Config.parseTomlRoot: Loaded " + (this.exclusions != null ? this.exclusions.size() : 0) + " exclusions");
            
            // Ensure all settings fields have proper defaults (handles missing fields from older configs)
            if (this.settings.getExcludedFileExtensions() == null) {
                this.settings.setExcludedFileExtensions(getDefaultExcludedFileExtensions());
            }
            if (this.settings.getExcludedMimeTypes() == null) {
                this.settings.setExcludedMimeTypes(getDefaultExcludedMimeTypes());
            }
            if (this.settings.getEnabledTools() == null) {
                Set<ToolType> defaultTools = new HashSet<>(Arrays.asList(
                    ToolType.TARGET, ToolType.PROXY, ToolType.SCANNER, ToolType.EXTENSIONS
                ));
                this.settings.setEnabledTools(defaultTools);
            }
            
            // Compile patterns with actual config values
            int minLength = this.settings.getGenericSecretMinLength();
            int maxLength = this.settings.getGenericSecretMaxLength();
            this.patterns.forEach(pattern -> pattern.compile(minLength, maxLength));
            
                    // Compile exclusions
        this.exclusions.forEach(exclusion -> {
            exclusion.compile();
            Logger.logCritical("Config.parseTomlRoot: Compiled exclusion - URLs: " + exclusion.getAllUrls() + ", Contexts: " + exclusion.getAllContexts());
        });
            
        }
    }
    
    /**
     * Validate configuration before accepting it (for imports)
     * Throws IllegalArgumentException with detailed error messages if validation fails
     */
    private void validateConfig(TomlRoot config) {
        List<String> errors = new ArrayList<>();
        
        // Required sections
        if (config.settings == null) {
            errors.add("Missing [settings] section");
        }
        if (config.patterns == null || config.patterns.isEmpty()) {
            errors.add("Missing [[patterns]] section or no patterns defined");
        }
        
        // Settings validation
        if (config.settings != null) {
            Settings s = config.settings;
            
            if (s.getWorkers() < 1 || s.getWorkers() > 100) {
                errors.add("Invalid workers count: " + s.getWorkers() + " (must be between 1 and 100)");
            }
            
            if (s.getGenericSecretMinLength() < 8 || s.getGenericSecretMinLength() > 128) {
                errors.add("Invalid generic_secret_min_length: " + s.getGenericSecretMinLength() + " (must be between 8 and 128)");
            }
            
            if (s.getGenericSecretMaxLength() < 8 || s.getGenericSecretMaxLength() > 256) {
                errors.add("Invalid generic_secret_max_length: " + s.getGenericSecretMaxLength() + " (must be between 8 and 256)");
            }
            
            if (s.getGenericSecretMinLength() > s.getGenericSecretMaxLength()) {
                errors.add("generic_secret_min_length (" + s.getGenericSecretMinLength() + 
                          ") cannot be greater than generic_secret_max_length (" + s.getGenericSecretMaxLength() + ")");
            }
            
            if (s.getDuplicateThreshold() < 1) {
                errors.add("Invalid duplicate_threshold: " + s.getDuplicateThreshold() + " (must be at least 1)");
            }
            
            if (s.getMaxHighlightsPerSecret() < 1) {
                errors.add("Invalid max_highlights_per_secret: " + s.getMaxHighlightsPerSecret() + " (must be at least 1)");
            }
            
            if (s.getExcludedFileExtensions() == null) {
                errors.add("Missing excluded_file_extensions array");
            }
            
            if (s.getExcludedMimeTypes() == null) {
                errors.add("Missing excluded_mime_types array");
            }
            
            if (s.getEnabledTools() == null || s.getEnabledTools().isEmpty()) {
                errors.add("Missing or empty enabled_tools array (at least one tool must be enabled)");
            }
        }
        
        // Pattern validation
        if (config.patterns != null) {
            Set<String> patternNames = new HashSet<>();
            int minLength = config.settings != null ? config.settings.getGenericSecretMinLength() : 15;
            int maxLength = config.settings != null ? config.settings.getGenericSecretMaxLength() : 80;
            
            for (PatternConfig p : config.patterns) {
                // Check for duplicate names
                if (patternNames.contains(p.getName())) {
                    errors.add("Duplicate pattern name: '" + p.getName() + "'");
                } else {
                    patternNames.add(p.getName());
                }
                
                // Check for null/empty name
                if (p.getName() == null || p.getName().trim().isEmpty()) {
                    errors.add("Pattern with empty or null name found");
                    continue;
                }
                
                // Check for null pattern field
                if (p.getPattern() == null) {
                    errors.add("Pattern '" + p.getName() + "' has null pattern field");
                    continue;
                }
                
                // Test regex compilation
                try {
                    p.compile(minLength, maxLength);
                } catch (Exception e) {
                    errors.add("Invalid regex in pattern '" + p.getName() + "': " + e.getMessage());
                }
            }
        }
        
        // Exclusion validation
        if (config.exclusions != null) {
            for (int i = 0; i < config.exclusions.size(); i++) {
                ExclusionConfig e = config.exclusions.get(i);
                
                // Check that at least one field is set
                List<String> allUrls = e.getAllUrls();
                List<String> allContexts = e.getAllContexts();
                
                if (allUrls.isEmpty() && allContexts.isEmpty()) {
                    errors.add("Exclusion #" + (i + 1) + " has no URL or context patterns defined");
                    continue;
                }
                
                // Test regex compilation for URLs
                for (String urlPattern : allUrls) {
                    try {
                        java.util.regex.Pattern.compile(urlPattern);
                    } catch (Exception ex) {
                        errors.add("Invalid URL regex in exclusion #" + (i + 1) + ": " + ex.getMessage());
                    }
                }
                
                // Test regex compilation for contexts
                for (String contextPattern : allContexts) {
                    try {
                        java.util.regex.Pattern.compile(contextPattern);
                    } catch (Exception ex) {
                        errors.add("Invalid context regex in exclusion #" + (i + 1) + ": " + ex.getMessage());
                    }
                }
            }
        }
        
        // Throw exception if any errors found
        if (!errors.isEmpty()) {
            throw new IllegalArgumentException(
                "Config validation failed:\n- " + String.join("\n- ", errors)
            );
        }
    }
    
    public void saveConfig() {
        
        // Update version to current extension version
        this.configVersion = getCurrentExtensionVersion();
        
        // Recompile patterns with current config values
        recompilePatterns();
        
        // Save to Burp persistence (single source of truth)
        saveToBurpPersistence();
        
        // Notify callback
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
        
        // Note: UI refresh is handled by specific methods when needed, not automatically
        // to prevent cascading refresh cycles
    }

    
    public void resetToDefaults() {
        loadDefaultConfig(); // Load defaults into memory
        saveConfig(); // Save to Burp persistence only
        
        // Notify UI to refresh if available
        if (AISecretsDetector.getInstance() != null) {
            UI ui = AISecretsDetector.getInstance().getUI();
            if (ui != null) {
                ui.refreshUI();
            }
        }
        
        Logger.logCritical("Configuration reset to defaults");
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
            String defaultRawToml = null;
            try (InputStream defaultConfigStream = getClass().getResourceAsStream(DEFAULT_CONFIG_PATH)) {
                if (defaultConfigStream != null) {
                    // Read raw TOML content
                    byte[] rawBytes = defaultConfigStream.readAllBytes();
                    defaultRawToml = new String(rawBytes, StandardCharsets.UTF_8);
                    
                    // Parse the raw TOML content
                    defaultTomlRoot = tomlMapper.readValue(defaultRawToml, TomlRoot.class);
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
            List<ExclusionConfig> userExclusions = new ArrayList<>(this.exclusions != null ? this.exclusions : new ArrayList<>());

            // Parse new defaults
            parseTomlRoot(defaultTomlRoot);

            // Restore user settings and exclusions
            this.settings = userSettings;
            this.exclusions = new CopyOnWriteArrayList<>(userExclusions);

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

    public List<ExclusionConfig> getExclusions() {
        if (exclusions == null) {
            return new ArrayList<>();
        }
        return new ArrayList<>(exclusions); // Return a copy
    }
    
    /**
     * Add a new exclusion configuration (new format)
     */
    public void addExclusion(String url, String context) {
        if (exclusions == null) {
            exclusions = new CopyOnWriteArrayList<>();
        }
        
        ExclusionConfig exclusion = new ExclusionConfig(url, context);
        exclusions.add(exclusion);
        
        Logger.logCritical("Config.addExclusion: Added exclusion - url: " + url + ", context: " + context);
        
        // Save configuration
        saveConfig();
    }

    /**
     * Add a new exclusion configuration with arrays (new format)
     */
    public void addExclusion(List<String> urls, List<String> contexts) {
        if (exclusions == null) {
            exclusions = new CopyOnWriteArrayList<>();
        }
        
        ExclusionConfig exclusion = new ExclusionConfig(urls, contexts);
        exclusions.add(exclusion);
        
        Logger.logCritical("Config.addExclusion: Added exclusion - urls: " + urls + ", contexts: " + contexts);
        
        // Save configuration
        saveConfig();
    }

    /**
     * Add a new exclusion configuration (backward compatibility)
     */
    @Deprecated
    public void addExclusion(String type, String regex, String patternName) {
        if (exclusions == null) {
            exclusions = new CopyOnWriteArrayList<>();
        }
        
        // Convert old format to new format
        if ("context".equals(type)) {
            addExclusion(null, regex); // No URL, just context
        } else if ("url".equals(type)) {
            addExclusion(regex, null); // Just URL, no context
        } else {
            addExclusion(null, regex); // Default to context
        }
    }
    
    /**
     * Add host exclusion (convenience method)
     */
    public void addHostExclusion(String host) {
        addExclusion(".*" + host + ".*", null); // URL pattern for host
    }
    
    /**
     * Add URL exclusion (convenience method)
     */
    public void addUrlExclusion(String url) {
        addExclusion(url, null); // URL-only exclusion
    }
    
    /**
     * Add context exclusion (convenience method)
     */
    public void addContextExclusion(String context, String patternName) {
        // Use context as regex pattern directly - more flexible
        addExclusion(null, context); // Context-only exclusion
    }
    

    
    /**
     * Generate smart context exclusion from selected text and matching pattern
     */
    public void addSmartContextExclusion(String selectedText, String patternName) {
        // For now, use the selected text as-is
        // In the future, we can implement smart pattern generation
        // that extracts the variable part and creates a more flexible regex
        addContextExclusion(selectedText, patternName);
    }
    
    /**
     * Remove an exclusion by index
     */
    public void removeExclusion(int index) {
        if (exclusions != null && index >= 0 && index < exclusions.size()) {
            ExclusionConfig removed = exclusions.remove(index);
            Logger.logCritical("Config.removeExclusion: Removed exclusion - URLs: " + removed.getAllUrls() + ", Contexts: " + removed.getAllContexts());
            saveConfig();
        }
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
        
        // Also recompile exclusions
        if (exclusions != null) {
            exclusions.forEach(exclusion -> exclusion.compile());
        }
    }
    
    public void exportConfigToFile(String filePath) throws IOException {
        Path destinationPath = Paths.get(filePath);
        Files.createDirectories(destinationPath.getParent());
        
        // Use Night-Config writer for beautiful TOML with triple quotes
        String tomlContent = TomlWriter.writeToString(this);
        Files.writeString(destinationPath, tomlContent, StandardCharsets.UTF_8);
        
        Logger.logCritical("Exported configuration to: " + destinationPath.toAbsolutePath());
    }
    
    public void importConfigFromFile(String filePath) throws IOException {
        Path sourcePath = Paths.get(filePath);
        if (!Files.exists(sourcePath)) {
            throw new IOException("File not found: " + filePath);
        }
        
        // Read and parse TOML content from file
        String importedTomlContent = Files.readString(sourcePath, StandardCharsets.UTF_8);
        TomlRoot tomlRoot = tomlMapper.readValue(importedTomlContent, TomlRoot.class);
        
        // VALIDATE strictly before accepting the configuration
        validateConfig(tomlRoot);
        
        // If validation passes, parse and apply the imported configuration
        parseTomlRoot(tomlRoot);
        
        // Update version to current extension version
        this.configVersion = getCurrentExtensionVersion();
        
        // Save to Burp persistence (single source of truth)
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
        
        Logger.logCritical("Imported configuration from: " + sourcePath.toAbsolutePath());
    }
    
    public String getDefaultConfigFilePath() {
        Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
        return configPath.toAbsolutePath().toString();
    }
    
    public boolean hasExportedConfigFile() {
        Path configPath = Paths.get(System.getProperty("user.home"), "burp-ai-secrets-detector", "config.toml");
        return Files.exists(configPath);
    }

} 