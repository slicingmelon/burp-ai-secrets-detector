/**
 * AI Secrets Detector
 * <p>
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * TOML writer using Night-Config with workaround for multiline literal bug
 */
package slicingmelon.aisecretsdetector;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.io.IndentStyle;

/**
 * Helper class to write TOML using Night-Config with triple-quoted literals for regex patterns.
 * 
 * NOTE: Night-Config has a bug in writeLiteralMultiline() that writes 4 quotes instead of 3.
 * We work around this with post-processing until the bug is fixed upstream.
 * See: https://github.com/TheElectronWill/night-config/blob/master/toml/src/main/java/com/electronwill/nightconfig/toml/StringWriter.java#L76
 */
public class TomlWriter {

    /**
     * Write Config to TOML string with proper formatting
     * - Triple-quoted literals (''') for regex patterns and empty strings
     * - Tab indentation
     * - Proper spacing between sections
     */
    public static String writeToString(Config config) {
        // Convert POJOs to Night-Config structure
        CommentedConfig nightConfig = TomlConverter.toNightConfig(config);
        
        // Configure writer
        com.electronwill.nightconfig.toml.TomlWriter writer = new com.electronwill.nightconfig.toml.TomlWriter();
        
        // Use tabs for indentation
        writer.setIndent(IndentStyle.TABS);
        
        // Use literal triple quotes only when needed (regex, quotes, empty string, newlines)
        writer.setWriteStringLiteralPredicate(TomlWriter::shouldUseLiteral);
        writer.setWriteStringMultilinePredicate(TomlWriter::shouldUseLiteral);
        
        // Don't indent array elements
        writer.setIndentArrayElementsPredicate(array -> false);
        
        // Don't write tables inline
        writer.setWriteTableInlinePredicate(table -> false);
        
        return writer.writeToString(nightConfig);
    }
    
    private static boolean shouldUseLiteral(String str) {
        if (str == null) {
            return false;
        }
        return str.isEmpty()
            || str.contains("\\")
            || str.contains("'")
            || str.contains("\n")
            || str.contains("\r");
    }
}
