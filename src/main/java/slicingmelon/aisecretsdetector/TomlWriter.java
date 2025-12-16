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

import java.util.IdentityHashMap;
import java.util.Map;

/**
 * Helper class to write TOML using Night-Config with triple-quoted literals for regex patterns.
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
        LiteralStringRegistry literalRegistry = new LiteralStringRegistry();
        CommentedConfig nightConfig = TomlConverter.toNightConfig(config, literalRegistry);
        
        // Configure writer
        com.electronwill.nightconfig.toml.TomlWriter writer = new com.electronwill.nightconfig.toml.TomlWriter();
        
        // Use tabs for indentation
        writer.setIndent(IndentStyle.TABS);
        
        // Use literal triple quotes only when needed (regex, quotes, empty string, newlines)
        writer.setWriteStringLiteralPredicate(str ->
            literalRegistry.isMarked(str) || defaultShouldUseLiteral(str));
        writer.setWriteStringMultilinePredicate(str ->
            literalRegistry.isMarked(str) || defaultShouldUseLiteral(str));
        
        // Don't indent array elements
        writer.setIndentArrayElementsPredicate(array -> false);
        
        // Don't write tables inline
        writer.setWriteTableInlinePredicate(table -> false);
        
        return writer.writeToString(nightConfig);
    }
    
    private static boolean defaultShouldUseLiteral(String str) {
        if (str == null) {
            return false;
        }
        return str.isEmpty()
            || str.contains("\\")
            || str.contains("'")
            || str.contains("\n")
            || str.contains("\r");
    }

    static final class LiteralStringRegistry {
        private final Map<String, Boolean> literals = new IdentityHashMap<>();

        String mark(String value) {
            if (value == null) {
                return null;
            }
            String unique = new String(value);
            literals.put(unique, Boolean.TRUE);
            return unique;
        }

        boolean isMarked(String value) {
            return value != null && literals.containsKey(value);
        }
    }
}
