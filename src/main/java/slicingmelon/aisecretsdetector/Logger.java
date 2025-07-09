/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * Unified logging system for the extension
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;

public class Logger {
    private static MontoyaApi api;
    
    /**
     * Initialize the logger with the Burp API
     * @param montoyaApi The Burp Montoya API instance
     */
    public static void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }
    
    /**
     * Log a message - only does UI logging if logging is enabled
     * For critical messages, use api.logging().logToOutput() directly
     * @param message The message to log
     */
    public static void logMsg(String message) {
        if (api != null) {
            try {
                AISecretsDetector detector = AISecretsDetector.getInstance();
                if (detector != null) {
                    Config config = detector.getConfig();
                    UI ui = detector.getUI();
                    
                    // Only log to UI if logging is enabled
                    if (config != null && config.getSettings().isLoggingEnabled() && ui != null) {
                        ui.appendToLog(message);
                    }
                } else {
                    // If detector not ready, do nothing (this is for verbose logging only)
                }
            } catch (Exception e) {
                // Silent failure for verbose logging
            }
        }
    }
    
    /**
     * Log an error message - only does UI logging if logging is enabled
     * For critical errors, use api.logging().logToError() directly
     * @param message The error message to log
     */
    public static void logErrorMsg(String message) {
        if (api != null) {
            try {
                AISecretsDetector detector = AISecretsDetector.getInstance();
                if (detector != null) {
                    Config config = detector.getConfig();
                    UI ui = detector.getUI();
                    
                    // Only log to UI if logging is enabled
                    if (config != null && config.getSettings().isLoggingEnabled() && ui != null) {
                        ui.appendToErrorLog(message);
                    }
                } else {
                    // If detector not ready, do nothing (this is for verbose logging only)
                }
            } catch (Exception e) {
                // Silent failure for verbose logging
            }
        }
    }
    
    /**
     * Log critical messages directly to Burp's output - always logs regardless of settings
     * Use this for extension startup, shutdown, and other critical events
     * @param message The critical message to log
     */
    public static void logCritical(String message) {
        if (api != null) {
            api.logging().logToOutput(message);
        } else {
            System.out.println(message);
        }
    }
    
    /**
     * Log critical errors directly to Burp's error stream - always logs regardless of settings
     * Use this for extension initialization failures and other critical errors
     * @param message The critical error message to log
     */
    public static void logCriticalError(String message) {
        if (api != null) {
            api.logging().logToError(message);
        } else {
            System.err.println(message);
        }
    }
} 