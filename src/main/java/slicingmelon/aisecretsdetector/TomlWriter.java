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
        // Single quotes in TOML are literal - no escaping needed for backslashes
        writer.setWriteStringLiteralPredicate(str -> true);
        
        // Use multiline mode for strings with backslashes or empty strings
        // This produces '''..''' format (but with newlines that we'll fix)
        writer.setWriteStringMultilinePredicate(str -> 
            str.contains("\\") || str.isEmpty()
        );
        
        // Don't indent array elements by default (keep arrays compact unless large)
        writer.setIndentArrayElementsPredicate(array -> false);
        
        // Write tables inline if they're small (not applicable for our config structure)
        writer.setWriteTableInlinePredicate(table -> false);
        
        // Generate TOML string
        String toml = writer.writeToString(nightConfig);
        
        // Post-process to fix multiline strings: convert '''\\n...\\n''' to '''...'''
        return fixMultilineStrings(toml);
    }
    
    /**
     * Fix multiline strings by removing unwanted newlines after opening ''' and before closing '''
     * 
     * Night-Config writes multiline literal strings as:
     * '''
     * content
     * ''''
     * 
     * We want inline format: '''content'''
     */
    private static String fixMultilineStrings(String toml) {
        // Replace '''\\n with ''' (remove newline after opening triple quotes)
        String fixed = toml.replaceAll("'''\\n", "'''");
        
        // Replace \\n'''' (newline + 4 quotes) with ''' (3 quotes)
        // Night-Config ends multiline literals with 4 quotes: ''''
        fixed = fixed.replaceAll("\\n''''", "'''");
        
        return fixed;
    }
}

