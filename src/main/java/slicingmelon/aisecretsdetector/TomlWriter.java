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
        
        // Use literal strings (single quotes) for ALL strings
        // Single quotes in TOML are literal - no escaping needed for backslashes
        writer.setWriteStringLiteralPredicate(str -> true);
        
        // Use multiline mode for strings with backslashes or empty strings
        // This produces ''' format (but with bugs that we'll fix via post-processing)
        writer.setWriteStringMultilinePredicate(str -> 
            str.contains("\\") || str.isEmpty()
        );
        
        // Don't indent array elements
        writer.setIndentArrayElementsPredicate(array -> false);
        
        // Don't write tables inline
        writer.setWriteTableInlinePredicate(table -> false);
        
        // Generate TOML string
        String toml = writer.writeToString(nightConfig);
        
        // WORKAROUND: Fix Night-Config's multiline literal bug
        return fixMultilineStrings(toml);
    }
    
    /**
     * Fix Night-Config's multiline literal string bugs:
     * 1. Remove unwanted newlines after opening ''' and before closing '''
     * 2. Fix the 4-quote bug (Night-Config writes '''' instead of ''')
     * 
     * Night-Config's writeLiteralMultiline() produces:
     * '''
     * content
     * ''''
     * 
     * We convert to valid TOML inline format: '''content'''
     * 
     * This workaround is needed until https://github.com/TheElectronWill/night-config
     * fixes the bug in StringWriter.writeLiteralMultiline() (line 76)
     */
    private static String fixMultilineStrings(String toml) {
        // Remove newline after opening triple quotes
        String fixed = toml.replaceAll("'''\\n", "'''");
        
        // Fix Night-Config's 4-quote bug: '''' -> '''
        // This is critical for producing valid TOML that can be parsed back
        fixed = fixed.replaceAll("\\n''''", "'''");
        
        return fixed;
    }
}
