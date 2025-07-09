/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Version utility to get the extension version
 */
package slicingmelon.aisecretsdetector;

import java.io.InputStream;
import java.util.Properties;

public class VersionUtil {
    private static final String VERSION_FILE = "/version.properties";
    private static String version = null;
    
    /**
     * Get the extension version from the version.properties file
     * @return The version string, or "unknown" if it cannot be determined
     */
    public static String getVersion() {
        if (version == null) {
            loadVersion();
        }
        return version;
    }
    
    /**
     * Load the version from the properties file
     */
    private static void loadVersion() {
        try (InputStream inputStream = VersionUtil.class.getResourceAsStream(VERSION_FILE)) {
            if (inputStream != null) {
                Properties properties = new Properties();
                properties.load(inputStream);
                version = properties.getProperty("version", "unknown");
            } else {
                version = "unknown";
            }
        } catch (Exception e) {
            version = "unknown";
        }
    }
    
    /**
     * Get a formatted version string for display
     * @return Formatted version string like "v1.7.1"
     */
    public static String getFormattedVersion() {
        String ver = getVersion();
        return "unknown".equals(ver) ? "unknown" : "v" + ver;
    }
} 