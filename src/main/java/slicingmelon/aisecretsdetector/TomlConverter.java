/**
 * AI Secrets Detector
 * <p>
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Converter between POJOs and Night-Config structures for beautiful TOML writing
 */
package slicingmelon.aisecretsdetector;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.toml.TomlFormat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Helper class to convert Config POJOs to Night-Config CommentedConfig structure
 * for writing beautiful TOML with triple quotes and proper formatting
 */
public class TomlConverter {

    /**
     * Convert Config POJOs to night-config CommentedConfig structure
     * for writing beautiful TOML with triple quotes
     */
    public static CommentedConfig toNightConfig(Config config, TomlWriter.LiteralStringRegistry literalRegistry) {
        CommentedConfig nc = TomlFormat.newConfig(LinkedHashMap::new);
        
        // Note: Version is NOT stored in TOML - it's managed separately in JAR manifest
        
        // Settings section (all fields)
        CommentedConfig settingsSection = nc.createSubConfig();
        Config.Settings s = config.getSettings();
        
        // Add settings in the same order as default-config.toml
        settingsSection.set("excluded_file_extensions", 
            new ArrayList<>(s.getExcludedFileExtensions()));
        settingsSection.set("excluded_mime_types", 
            new ArrayList<>(s.getExcludedMimeTypes()));
        settingsSection.set("workers", s.getWorkers());
        settingsSection.set("in_scope_only", s.isInScopeOnly());
        settingsSection.set("logging_enabled", s.isLoggingEnabled());
        settingsSection.set("randomness_algorithm_enabled", s.isRandomnessAlgorithmEnabled());
        settingsSection.set("generic_secret_min_length", s.getGenericSecretMinLength());
        settingsSection.set("generic_secret_max_length", s.getGenericSecretMaxLength());
        settingsSection.set("duplicate_threshold", s.getDuplicateThreshold());
        settingsSection.set("max_highlights_per_secret", s.getMaxHighlightsPerSecret());
        settingsSection.set("enabled_tools", 
            s.getEnabledTools().stream()
                .map(Enum::name)
                .collect(Collectors.toList()));
        
        nc.set("settings", settingsSection);
        
        // Exclusions array (if any)
        List<CommentedConfig> exclusionsArray = new ArrayList<>();
        for (Config.ExclusionConfig e : config.getExclusions()) {
            CommentedConfig ec = nc.createSubConfig();
            
            if (e.getUrl() != null && !e.getUrl().trim().isEmpty()) {
                ec.set("url", e.getUrl());
            }
            
            if (e.getContext() != null && !e.getContext().trim().isEmpty()) {
                ec.set("context", e.getContext());
            }
            
            exclusionsArray.add(ec);
        }
        if (!exclusionsArray.isEmpty()) {
            nc.set("exclusions", exclusionsArray);
        }
        
        // Patterns array (50+ patterns)
        List<CommentedConfig> patternsArray = new ArrayList<>();
        for (Config.PatternConfig p : config.getPatterns()) {
            CommentedConfig pc = nc.createSubConfig();
            pc.set("name", p.getName());
            pc.set("prefix", literalRegistry.mark(p.getPrefix() != null ? p.getPrefix() : ""));
            pc.set("pattern", literalRegistry.mark(p.getPattern() != null ? p.getPattern() : ""));
            pc.set("suffix", literalRegistry.mark(p.getSuffix() != null ? p.getSuffix() : ""));
            patternsArray.add(pc);
        }
        nc.set("patterns", patternsArray);
        
        return nc;
    }
}

