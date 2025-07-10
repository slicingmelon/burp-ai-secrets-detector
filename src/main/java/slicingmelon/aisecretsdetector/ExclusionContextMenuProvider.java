package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.core.Range;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Context menu provider for creating exclusions from selected text.
 * Allows users to select text in HTTP responses and automatically generate
 * exclusion rules based on matching secret patterns.
 */
public class ExclusionContextMenuProvider implements ContextMenuItemsProvider {
    
    private final MontoyaApi api;
    private final Config config;
    private final SecretScanner secretScanner;
    
    public ExclusionContextMenuProvider(MontoyaApi api, Config config, SecretScanner secretScanner) {
        this.api = api;
        this.config = config;
        this.secretScanner = secretScanner;
    }
    
    @Override
    public List<java.awt.Component> provideMenuItems(ContextMenuEvent event) {
        List<java.awt.Component> menuItems = new ArrayList<>();
        
        // Debug logging
        api.logging().logToOutput("ExclusionContextMenuProvider: provideMenuItems called");
        api.logging().logToOutput("Invocation type: " + event.invocationType());
        api.logging().logToOutput("Message editor present: " + event.messageEditorRequestResponse().isPresent());
        
        try {
                        // Check if this is a message editor context (request or response)
            if (event.messageEditorRequestResponse().isPresent()) {
                MessageEditorHttpRequestResponse messageEditor = event.messageEditorRequestResponse().get();
                
                // Always show the menu item - we'll handle no selection in the action listener
                api.logging().logToOutput("Creating context menu item (always show)");
                JMenuItem excludeMenuItem = new JMenuItem("Exclude findings matching selected context");
                excludeMenuItem.addActionListener(new ExclusionActionListener(messageEditor));
                menuItems.add(excludeMenuItem);
                api.logging().logToOutput("Menu item added to list");
            }
        } catch (Exception e) {
            // Log error but don't break the context menu
            api.logging().logToError("Error in context menu provider: " + e.getMessage());
        }
        
        return menuItems;
    }
    
    /**
     * Action listener for the exclusion menu item
     */
    private class ExclusionActionListener implements ActionListener {
        private final MessageEditorHttpRequestResponse messageEditor;
        
        public ExclusionActionListener(MessageEditorHttpRequestResponse messageEditor) {
            this.messageEditor = messageEditor;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
            // Check if there's a selection
            if (!messageEditor.selectionOffsets().isPresent()) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null, 
                            "Please select a portion of text from the response around the red marker (secret finding) that you want to exclude.", 
                            "No Text Selected", JOptionPane.INFORMATION_MESSAGE);
                });
                return;
            }
            
            // Get the selected text
            Range selection = messageEditor.selectionOffsets().get();
            String selectedText = null;
            
            if (messageEditor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST) {
                selectedText = messageEditor.requestResponse().request().toString()
                        .substring(selection.startIndexInclusive(), selection.endIndexExclusive());
            } else if (messageEditor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE) {
                selectedText = messageEditor.requestResponse().response().toString()
                        .substring(selection.startIndexInclusive(), selection.endIndexExclusive());
            }
            
            if (selectedText == null || selectedText.trim().isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null, 
                            "Please select a portion of text from the response around the red marker (secret finding) that you want to exclude.", 
                            "No Valid Text Selected", JOptionPane.INFORMATION_MESSAGE);
                });
                return;
            }
            
            generateExclusionsFromContext(selectedText);
        }
    }
    
    /**
     * Generate exclusions from the selected context text.
     * This method runs all configured patterns against the selected text
     * and creates dynamic exclusion rules for each pattern that matches.
     */
    private void generateExclusionsFromContext(String selectedText) {
        try {
            api.logging().logToOutput("=== generateExclusionsFromContext called ===");
            api.logging().logToOutput("Selected text length: " + selectedText.length());
            api.logging().logToOutput("Selected text: " + selectedText);
            api.logging().logToOutput("=== Starting pattern matching ===");
            
            List<String> generatedExclusions = new ArrayList<>();
            int exclusionCount = 0;
            
            // Get all patterns from config
            List<Config.PatternConfig> patterns = config.getPatterns();
            api.logging().logToOutput("Total patterns to test: " + patterns.size());
            
            for (Config.PatternConfig patternConfig : patterns) {
                String patternName = patternConfig.getName();
                String prefix = patternConfig.getPrefix();
                String pattern = patternConfig.getPattern();
                String suffix = patternConfig.getSuffix();
                
                // Build the full regex pattern with proper min/max lengths
                String fullPattern = buildFullPattern(prefix, pattern, suffix);
                
                api.logging().logToOutput("Testing pattern '" + patternName + "' against selected text");
                api.logging().logToOutput("Full pattern: " + fullPattern);
                
                try {
                    Pattern compiledPattern = Pattern.compile(fullPattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    Matcher matcher = compiledPattern.matcher(selectedText);
                    
                    if (matcher.find()) {
                        api.logging().logToOutput("Pattern '" + patternName + "' MATCHED! Full match: " + matcher.group(0));
                        // Generate dynamic exclusion
                        api.logging().logToOutput("Generating dynamic exclusion for pattern: " + patternName);
                        String exclusionRegex = generateDynamicExclusion(selectedText, matcher, pattern);
                        
                        api.logging().logToOutput("Generated exclusion regex: " + exclusionRegex);
                        
                        if (exclusionRegex != null) {
                            // Add exclusion to config
                            config.addExclusion("context", exclusionRegex, patternName);
                            generatedExclusions.add(String.format("Pattern '%s': %s", patternName, exclusionRegex));
                            exclusionCount++;
                            api.logging().logToOutput("Successfully added exclusion for pattern: " + patternName);
                        } else {
                            api.logging().logToOutput("Failed to generate exclusion regex for pattern: " + patternName);
                        }
                    } else {
                        api.logging().logToOutput("Pattern '" + patternName + "' did NOT match");
                    }
                } catch (Exception ex) {
                    api.logging().logToError("Error processing pattern '" + patternName + "': " + ex.getMessage());
                    ex.printStackTrace();
                }
            }
            
            // Save config if exclusions were added
            if (exclusionCount > 0) {
                config.saveConfig();
                
                // Show success message
                String message = String.format("Generated %d exclusion(s) from selected context:\n\n%s", 
                        exclusionCount, String.join("\n", generatedExclusions));
                
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null, message, "Exclusions Generated", JOptionPane.INFORMATION_MESSAGE);
                });
                
                // Log the action
                AISecretsDetector.getInstance().logMsg("Generated " + exclusionCount + " exclusions from context menu");
            } else {
                // Show no matches message
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(null, 
                            "No secret patterns matched the selected context.\nTry selecting text that contains the secret you want to exclude.", 
                            "No Matches Found", JOptionPane.INFORMATION_MESSAGE);
                });
            }
            
        } catch (Exception ex) {
            api.logging().logToError("Error generating exclusions from context: " + ex.getMessage());
            ex.printStackTrace();
            
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null, 
                        "Error generating exclusions: " + ex.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
    }
    
    /**
     * Build the full regex pattern from prefix, pattern, and suffix
     */
    private String buildFullPattern(String prefix, String pattern, String suffix) {
        StringBuilder fullPattern = new StringBuilder();
        
        if (prefix != null && !prefix.isEmpty()) {
            fullPattern.append(replacePlaceholders(prefix));
        }
        
        if (pattern != null && !pattern.isEmpty()) {
            fullPattern.append(replacePlaceholders(pattern));
        }
        
        if (suffix != null && !suffix.isEmpty()) {
            fullPattern.append(replacePlaceholders(suffix));
        }
        
        return fullPattern.toString();
    }
    
    /**
     * Replace placeholders in regex patterns with actual config values
     */
    private String replacePlaceholders(String text) {
        if (text == null) return text;
        
        // Get min/max lengths from config
        int minLength = config.getSettings().getGenericSecretMinLength();
        int maxLength = config.getSettings().getGenericSecretMaxLength();
        
        // Replace placeholders with actual values
        String result = text.replace("generic_secret_min_length", String.valueOf(minLength));
        result = result.replace("generic_secret_max_length", String.valueOf(maxLength));
        
        return result;
    }
    
    /**
     * Generate a dynamic exclusion regex by replacing the secret portion
     * with the pattern that would match it
     */
    private String generateDynamicExclusion(String selectedText, Matcher matcher, String secretPattern) {
        try {
            api.logging().logToOutput("=== generateDynamicExclusion called ===");
            
            // Get the matched secret (group 1)
            String matchedSecret = matcher.group(1);
            
            api.logging().logToOutput("Selected text: " + selectedText);
            api.logging().logToOutput("Matched secret: " + matchedSecret);
            api.logging().logToOutput("Secret pattern: " + secretPattern);
            
            // Simple replacement: replace the actual secret with the pattern
            String exclusionRegex = selectedText.replace(matchedSecret, secretPattern);
            
            api.logging().logToOutput("Final exclusion regex: " + exclusionRegex);
            
            return exclusionRegex;
            
        } catch (Exception ex) {
            api.logging().logToError("Error generating dynamic exclusion: " + ex.getMessage());
            ex.printStackTrace();
            return null;
        }
    }
} 