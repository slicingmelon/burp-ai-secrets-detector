package slicingmelon.aisecretsdetector;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.UnmodifiableConfig;
import com.electronwill.nightconfig.toml.TomlWriter;

import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * A custom TomlWriter that forces specific keys to be written with triple-quotes
 * to preserve raw regex strings without unwanted escaping or newlines.
 */
public class CustomTomlWriter extends TomlWriter {
    private static final Set<String> FORCE_TRIPLE_QUOTE_KEYS = new HashSet<>(Arrays.asList("pattern", "prefix", "suffix"));

    /**
     * Overrides the default entry writing logic. If the entry's key is one of the special
     * keys ("pattern", "prefix", "suffix"), we write its string value as a raw, single-line,
     * triple-quoted string ('''). Otherwise, we fall back to the default TomlWriter behavior.
     */
    @Override
    protected void writeEntry(UnmodifiableConfig.Entry entry, Writer writer) throws IOException {
        String key = entry.getKey();
        Object value = entry.getRawValue();

        if (value instanceof String && FORCE_TRIPLE_QUOTE_KEYS.contains(key)) {
            // This is a special key that we want to format as '''...''' on a single line.
            // We replicate the structure of the original writeEntry method but substitute our
            // custom value-writing logic.
            
            // Write the comment, if any, by calling the protected method from the parent class.
            String comment = (entry instanceof CommentedConfig.Entry) ? ((CommentedConfig.Entry) entry).getComment() : null;
            if (comment != null) {
                writeComment(comment, writer);
            }

            // Write the key, calling the protected method from the parent class.
            writeKey(key, writer);
            writer.write(" = ");

            // Write the value with forced single-line triple quotes.
            writer.write("'''");
            writer.write((String) value);
            writer.write("'''");
        } else {
            // This is not one of our special keys, so we let the parent class handle it with its
            // default logic.
            super.writeEntry(entry, writer);
        }
    }
} 