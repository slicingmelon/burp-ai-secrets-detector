package com.electronwill.nightconfig.toml;

import static com.electronwill.nightconfig.core.utils.StringUtils.splitLines;

import java.util.Iterator;

import com.electronwill.nightconfig.core.io.CharacterOutput;

/**
 * Copied from night-config 3.8.3 to patch literal multiline handling until the
 * upstream fix is released.
 */
final class StringWriter {
	private static final char[] ESCAPED_B = {'\\', 'b'},
								ESCAPED_F = {'\\', 'f'},
								ESCAPED_N = {'\\', 'n'},
								ESCAPED_R = {'\\', 'r'},
								ESCAPED_T = {'\\', 't'},
								ESCAPED_BACKSLASH = {'\\', '\\'},
								ESCAPED_QUOTE = {'\\', '\"'};

	static void writeBasic(String str, CharacterOutput output) {
		output.write('\"');
		str.codePoints().forEach(c -> writeBasicChar(c, output));
		output.write('\"');
	}

	static void writeBasicMultiline(String str, CharacterOutput output, TomlWriter writer) {
		output.write("\"\"\""); // """\
		for (Iterator<String> it = splitLines(str).iterator(); it.hasNext();) {
			String line = it.next();
			writer.writeNewline(output);
			char[] chars = line.toCharArray();
			for (int i = 0; i < chars.length; i++) {
				char c = chars[i];
				switch (c) {
					case '\"': {
						if ((i+1 == chars.length && !it.hasNext()) || ((i+1 < chars.length && chars[i+1] == '\"') && (i+2 < chars.length && chars[i+2] == '\"') && (i+3 < chars.length))) {
							output.write(ESCAPED_QUOTE);
						} else {
							output.write(c);
						}
						break;
					}
					case '\b':
						output.write(ESCAPED_B);
						break;
					case '\f':
						output.write(ESCAPED_F);
						break;
					case '\\':
						output.write(ESCAPED_BACKSLASH);
						break;
					default: {
						if (c != '\t' && c != '\n' && c != '\r' && Toml.isControlChar(c)) {
							output.write(escapeUnicode(c));
						} else {
							output.write(Character.toChars(c));
						}
						break;
					}
				}
			}
		}
		output.write("\"\"\"");
	}

	static void writeLiteral(String str, CharacterOutput output) {
		output.write('\'');
		output.write(str);
		output.write('\'');
	}

	static void writeLiteralMultiline(String str, CharacterOutput output) {
		boolean hasLineBreak = containsLineBreak(str);
		output.write("'''");
		if (hasLineBreak) {
			output.write('\n');
			output.write(str);
			if (!endsWithLineBreak(str)) {
				output.write('\n');
			}
		} else {
			output.write(str);
		}
		output.write("'''");
	}

	private static boolean containsLineBreak(String str) {
		return str.indexOf('\n') >= 0 || str.indexOf('\r') >= 0;
	}

	private static boolean endsWithLineBreak(String str) {
		if (str.isEmpty()) {
			return false;
		}
		char last = str.charAt(str.length() - 1);
		return last == '\n' || last == '\r';
	}

	private static void writeBasicChar(int c, CharacterOutput output) {
		switch (c) {
			case '\\':
				output.write(ESCAPED_BACKSLASH);
				break;
			case '\"':
				output.write(ESCAPED_QUOTE);
				break;
			case '\b':
				output.write(ESCAPED_B);
				break;
			case '\f':
				output.write(ESCAPED_F);
				break;
			case '\n':
				output.write(ESCAPED_N);
				break;
			case '\r':
				output.write(ESCAPED_R);
				break;
			case '\t':
				output.write(ESCAPED_T);
				break;
			default: {
				if (Toml.isControlChar(c)) {
					output.write(escapeUnicode(c));
				} else {
					output.write(Character.toChars(c));
				}
				break;
			}
		}
	}

	static String escapeUnicode(int codePoint) {
		String hexa = Integer.toHexString(codePoint).toUpperCase();
		if (hexa.length() < 4) {
			while (hexa.length() < 4) {
				hexa = "0" + hexa;
			}
		} else if (hexa.length() < 8) {
			while (hexa.length() < 8) {
				hexa = "0" + hexa;
			}
		}
		return "\\u" + hexa;
	}

	private StringWriter() {}
}

