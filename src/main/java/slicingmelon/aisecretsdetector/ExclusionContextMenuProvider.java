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
        
        // Only show menu items for HTTP message editor contexts
        if (event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST || 
            event.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE) {
            
            // Check if there's a selection
            if (event.messageEditorRequestResponse().isPresent()) {
                MessageEditorHttpRequestResponse messageEditor = event.messageEditorRequestResponse().get();
                
                // For response context with selection
                if (event.invocationType() == InvocationType.MESSAGE_EDITOR_RESPONSE && 
                    messageEditor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE &&
                    messageEditor.selectionOffsets().isPresent()) {
                    
                    Range selection = messageEditor.selectionOffsets().get();
                    String selectedText = messageEditor.requestResponse().response().bodyToString()
                            .substring(selection.startIndexInclusive(), selection.endIndexExclusive());
                    
                    if (!selectedText.trim().isEmpty()) {
                        JMenuItem excludeMenuItem = new JMenuItem("Exclude findings matching selected context");
                        excludeMenuItem.addActionListener(new ExclusionActionListener(selectedText));
                        menuItems.add(excludeMenuItem);
                    }
                }
            }
        }
        
        return menuItems;
    }
    
    /**
     * Action listener for the exclusion menu item
     */
    private class ExclusionActionListener implements ActionListener {
        private final String selectedText;
        
        public ExclusionActionListener(String selectedText) {
            this.selectedText = selectedText;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
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
            List<String> generatedExclusions = new ArrayList<>();
            int exclusionCount = 0;
            
            // Get all patterns from config
            List<Config.PatternConfig> patterns = config.getPatterns();
            
            for (Config.PatternConfig patternConfig : patterns) {
                String patternName = patternConfig.getName();
                String prefix = patternConfig.getPrefix();
                String pattern = patternConfig.getPattern();
                String suffix = patternConfig.getSuffix();
                
                // Build the full regex pattern
                String fullPattern = buildFullPattern(prefix, pattern, suffix);
                
                try {
                    Pattern compiledPattern = Pattern.compile(fullPattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    Matcher matcher = compiledPattern.matcher(selectedText);
                    
                    if (matcher.find()) {
                        // Generate dynamic exclusion
                        String exclusionRegex = generateDynamicExclusion(selectedText, matcher, pattern);
                        
                        if (exclusionRegex != null) {
                            // Add exclusion to config
                            config.addExclusion("context", exclusionRegex, patternName);
                            generatedExclusions.add(String.format("Pattern '%s': %s", patternName, exclusionRegex));
                            exclusionCount++;
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("Error processing pattern '" + patternName + "': " + ex.getMessage());
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
            fullPattern.append(prefix);
        }
        
        if (pattern != null && !pattern.isEmpty()) {
            fullPattern.append(pattern);
        }
        
        if (suffix != null && !suffix.isEmpty()) {
            fullPattern.append(suffix);
        }
        
        return fullPattern.toString();
    }
    
    /**
     * Generate a dynamic exclusion regex by replacing the secret portion
     * with the pattern that would match it
     */
    private String generateDynamicExclusion(String selectedText, Matcher matcher, String secretPattern) {
        try {
            // Get the full match
            String fullMatch = matcher.group(0);
            int matchStart = matcher.start();
            int matchEnd = matcher.end();
            
            // Split the selected text into: before match + match + after match
            String before = selectedText.substring(0, matchStart);
            String after = selectedText.substring(matchEnd);
            
            // Escape special regex characters in the before and after parts
            String escapedBefore = Pattern.quote(before);
            String escapedAfter = Pattern.quote(after);
            
            // Build dynamic exclusion: literal before + secret pattern + literal after
            StringBuilder exclusionRegex = new StringBuilder();
            exclusionRegex.append(escapedBefore);
            exclusionRegex.append(secretPattern); // Use the secret pattern from config
            exclusionRegex.append(escapedAfter);
            
            return exclusionRegex.toString();
            
        } catch (Exception ex) {
            api.logging().logToError("Error generating dynamic exclusion: " + ex.getMessage());
            return null;
        }
    }
} 