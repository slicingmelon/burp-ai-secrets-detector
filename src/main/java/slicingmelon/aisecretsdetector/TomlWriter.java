/**
 * AI Secrets Detector
 * <p>
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * TOML writer using Night-Config for beautiful formatting
 */
package slicingmelon.aisecretsdetector;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.io.IndentStyle;

/**
 * Helper class to write beautiful TOML using Night-Config
 * with triple-quoted literals for regex patterns
 */
public class TomlWriter {

    /**
     * Write Config to TOML string with beautiful formatting
     * - Triple-quoted literals for regex patterns and empty strings
     * - Tab indentation
     * - Proper spacing between sections
     */
    public static String writeToString(Config config) {
        // Convert POJOs to Night-Config structure
        CommentedConfig nightConfig = TomlConverter.toNightConfig(config);
        
        // Configure writer for beautiful output
        com.electronwill.nightconfig.toml.TomlWriter writer = new com.electronwill.nightconfig.toml.TomlWriter();
        
        // Use tabs for indentation
        writer.setIndent(IndentStyle.TABS);
        
        // Use literal strings (single quotes) for all strings
        // This is required for triple-quoted literals to work
        writer.setWriteStringLiteralPredicate(str -> true);
        
        // Use multiline (triple quotes) for:
        // 1. Strings containing backslashes (regex patterns)
        // 2. Empty strings (to get '''''')
        // When combined with writeStringLiteralPredicate=true, this produces '''...'''
        writer.setWriteStringMultilinePredicate(str -> 
            str.contains("\\") || str.isEmpty()
        );
        
        // Don't indent array elements by default (keep arrays compact unless large)
        writer.setIndentArrayElementsPredicate(array -> false);
        
        // Write tables inline if they're small (not applicable for our config structure)
        writer.setWriteTableInlinePredicate(table -> false);
        
        // Generate TOML string
        return writer.writeToString(nightConfig);
    }
}

