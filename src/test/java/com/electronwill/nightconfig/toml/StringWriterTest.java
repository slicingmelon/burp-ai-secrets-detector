package com.electronwill.nightconfig.toml;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.StringWriter;

import org.junit.jupiter.api.Test;

import com.electronwill.nightconfig.core.io.WriterOutput;

class StringWriterTest {

    @Test
    void literalMultilineKeepsSingleLineStringsInline() {
        java.io.StringWriter buffer = new java.io.StringWriter();
        WriterOutput output = new WriterOutput(buffer);

        StringWriter.writeLiteralMultiline("(?i)\\btest", output);

        assertEquals("'''(?i)\\btest'''", buffer.toString());
    }

    @Test
    void literalMultilineAddsNewlinesWhenNeeded() {
        java.io.StringWriter buffer = new java.io.StringWriter();
        WriterOutput output = new WriterOutput(buffer);

        StringWriter.writeLiteralMultiline("line1\nline2", output);

        assertEquals("'''\nline1\nline2\n'''", buffer.toString());
    }
}

