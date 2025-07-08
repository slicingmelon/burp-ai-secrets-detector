/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

public class UI {
    private MontoyaApi api;
    private Config config;
    private JTextArea logArea;
    private static UI instance;
    
    public static UI getInstance() {
        return instance;
    }

    public UI(MontoyaApi api) {
        this.api = api;
        this.config = Config.getInstance();
        instance = this;
    }
    
    public JComponent createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Settings panel - now uses a split layout
        JPanel settingsPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        
        // Left panel - for worker settings and in-scope only
        JPanel leftPanel = new JPanel(new GridBagLayout());
        GridBagConstraints leftConstraints = new GridBagConstraints();
        leftConstraints.fill = GridBagConstraints.HORIZONTAL;
        leftConstraints.insets = new Insets(5, 5, 5, 5);
        leftConstraints.anchor = GridBagConstraints.WEST; // Anchor to the west (left)
        
        // Worker setting
        JLabel workersLabel = new JLabel("Number of Workers:");
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 0;
        leftConstraints.weightx = 0.0; // Don't resize the label
        leftPanel.add(workersLabel, leftConstraints);
        
        SpinnerNumberModel workersModel = new SpinnerNumberModel(
                config.getSettings().getWorkers(),
                1,
                50,
                1
        );
        JSpinner workersSpinner = new JSpinner(workersModel);
        
        // Fix the spinner width using a more direct approach
        JComponent editor = workersSpinner.getEditor();
        Dimension prefSize = new Dimension(60, editor.getPreferredSize().height);
        editor.setPreferredSize(prefSize);
        
        // Set the spinner's maximum size to ensure it doesn't grow beyond our desired size
        workersSpinner.setMaximumSize(new Dimension(60, workersSpinner.getPreferredSize().height));
        
        // Additionally, add the spinner to a panel with FlowLayout to prevent stretching
        JPanel spinnerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        spinnerPanel.setOpaque(false); // Make panel transparent
        spinnerPanel.add(workersSpinner);
        
        workersSpinner.addChangeListener(_ -> {
            config.getSettings().setWorkers((Integer) workersSpinner.getValue());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Workers: " + config.getSettings().getWorkers());
        });
        
        leftConstraints.gridx = 1;
        leftConstraints.gridy = 0;
        leftConstraints.weightx = 0.0; // Don't stretch
        leftPanel.add(spinnerPanel, leftConstraints);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", config.getSettings().isInScopeOnly());
        inScopeCheckbox.addActionListener(_ -> {
            config.getSettings().setInScopeOnly(inScopeCheckbox.isSelected());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - In-Scope Only: " + config.getSettings().isInScopeOnly());
        });
        
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 1;
        leftConstraints.gridwidth = 2;
        leftConstraints.weightx = 1.0;
        leftPanel.add(inScopeCheckbox, leftConstraints);
        
        // Right panel - for randomness algorithm settings
        JPanel rightPanel = new JPanel(new GridBagLayout());
        GridBagConstraints rightConstraints = new GridBagConstraints();
        rightConstraints.fill = GridBagConstraints.HORIZONTAL;
        rightConstraints.insets = new Insets(5, 5, 5, 5);
        rightConstraints.anchor = GridBagConstraints.WEST; // Anchor to the west (left)
        
        // Randomness Algorithm Enable
        JCheckBox randomnessCheckbox = new JCheckBox("Enable Randomness Algorithm Detection", 
                                                   config.getSettings().isRandomnessAlgorithmEnabled());
        randomnessCheckbox.addActionListener(_ -> {
            config.getSettings().setRandomnessAlgorithmEnabled(randomnessCheckbox.isSelected());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Randomness Algorithm: " +
                    config.getSettings().isRandomnessAlgorithmEnabled());
        });
        
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 0;
        rightConstraints.gridwidth = 2;
        rightPanel.add(randomnessCheckbox, rightConstraints);
        
        // Min Length setting
        JLabel minLengthLabel = new JLabel("Generic Secret Min Length (Randomness Algorithm):");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 1;
        rightConstraints.gridwidth = 1;
        rightConstraints.weightx = 0.0; // Don't resize the label
        rightPanel.add(minLengthLabel, rightConstraints);
        
        SpinnerNumberModel minLengthModel = new SpinnerNumberModel(
                config.getSettings().getGenericSecretMinLength(),
                8,   // Minimum allowed value
                128, // Maximum allowed value for min length
                1
        );
        JSpinner minLengthSpinner = new JSpinner(minLengthModel);
        minLengthSpinner.addChangeListener(_ -> {
            config.getSettings().setGenericSecretMinLength((Integer) minLengthSpinner.getValue());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Min Secret Length: " +
                    config.getSettings().getGenericSecretMinLength());
        });
        
        // Set a reasonable fixed width for the spinner
        JComponent minEditor = minLengthSpinner.getEditor();
        Dimension minPrefSize = new Dimension(60, minEditor.getPreferredSize().height);
        minEditor.setPreferredSize(minPrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 1;
        rightConstraints.weightx = 0.0; // Don't stretch the spinner
        rightPanel.add(minLengthSpinner, rightConstraints);
        
        // Max Length setting
        JLabel maxLengthLabel = new JLabel("Generic Secret Max Length (Randomness Algorithm):");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 2;
        rightConstraints.weightx = 0.0; // Don't resize the label
        rightPanel.add(maxLengthLabel, rightConstraints);
        
        SpinnerNumberModel maxLengthModel = new SpinnerNumberModel(
                config.getSettings().getGenericSecretMaxLength(),
                8,   // Minimum allowed value for max length
                128, // Maximum allowed value
                1
        );
        JSpinner maxLengthSpinner = new JSpinner(maxLengthModel);
        maxLengthSpinner.addChangeListener(_ -> {
            config.getSettings().setGenericSecretMaxLength((Integer) maxLengthSpinner.getValue());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Max Secret Length: " +
                    config.getSettings().getGenericSecretMaxLength());
        });
        
        // Set a reasonable fixed width for the spinner
        JComponent maxEditor = maxLengthSpinner.getEditor();
        Dimension maxPrefSize = new Dimension(60, maxEditor.getPreferredSize().height);
        maxEditor.setPreferredSize(maxPrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 2;
        rightConstraints.weightx = 0.0;
        rightPanel.add(maxLengthSpinner, rightConstraints);
        
        // Duplicate Threshold setting
        JLabel duplicateThresholdLabel = new JLabel("Duplicate Secret Threshold (same secret value across target host):");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 3;
        rightConstraints.weightx = 0.0;
        rightPanel.add(duplicateThresholdLabel, rightConstraints);
        
        SpinnerNumberModel duplicateThresholdModel = new SpinnerNumberModel(
                config.getSettings().getDuplicateThreshold(),
                1,   // Minimum value
                50,  // Maximum value
                1
        );
        JSpinner duplicateThresholdSpinner = new JSpinner(duplicateThresholdModel);
        duplicateThresholdSpinner.addChangeListener(_ -> {
            config.getSettings().setDuplicateThreshold((Integer) duplicateThresholdSpinner.getValue());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Duplicate Threshold: " +
                    config.getSettings().getDuplicateThreshold());
        });
        
        // Set a reasonable fixed width for the spinner
        JComponent thresholdEditor = duplicateThresholdSpinner.getEditor();
        Dimension thresholdPrefSize = new Dimension(60, thresholdEditor.getPreferredSize().height);
        thresholdEditor.setPreferredSize(thresholdPrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 3;
        rightConstraints.weightx = 0.0;
        rightPanel.add(duplicateThresholdSpinner, rightConstraints);
        
        // Max Highlights Per Secret setting
        JLabel maxHighlightsLabel = new JLabel("Max Highlights Per Unique Secret In Response:");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 4;
        rightConstraints.weightx = 0.0;
        rightPanel.add(maxHighlightsLabel, rightConstraints);
        
        SpinnerNumberModel maxHighlightsModel = new SpinnerNumberModel(
                config.getSettings().getMaxHighlightsPerSecret(),
                1,   // Minimum value
                50,  // Maximum value
                1
        );
        JSpinner maxHighlightsSpinner = new JSpinner(maxHighlightsModel);
        maxHighlightsSpinner.addChangeListener(_ -> {
            config.getSettings().setMaxHighlightsPerSecret((Integer) maxHighlightsSpinner.getValue());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Max Highlights Per Secret: " +
                    config.getSettings().getMaxHighlightsPerSecret());
        });
        
        // Set a reasonable fixed width for the spinner
        JComponent highlightsEditor = maxHighlightsSpinner.getEditor();
        Dimension highlightsPrefSize = new Dimension(60, highlightsEditor.getPreferredSize().height);
        highlightsEditor.setPreferredSize(highlightsPrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 4;
        rightConstraints.weightx = 0.0;
        rightPanel.add(maxHighlightsSpinner, rightConstraints);
        
        // Setting panel - left and right panels
        settingsPanel.add(leftPanel);
        settingsPanel.add(rightPanel);
        
        // Tool source settings
        JPanel toolsPanel = new JPanel();
        toolsPanel.setBorder(BorderFactory.createTitledBorder("Process Messages from Tools:"));
        toolsPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 10, 0)); // Use FlowLayout with LEFT alignment and horizontal gap
        
        Map<ToolType, JCheckBox> toolCheckboxes = new HashMap<>();
        
        ToolType[] relevantTools = {
            ToolType.TARGET, ToolType.PROXY, ToolType.SCANNER, 
            ToolType.EXTENSIONS, ToolType.REPEATER, ToolType.INTRUDER
        };
        
        // Single row for all tool checkboxes
        for (ToolType tool : relevantTools) {
            JCheckBox checkbox = new JCheckBox(tool.name(), config.getSettings().isToolEnabled(tool));
            checkbox.addActionListener(_ -> {
                config.getSettings().setToolEnabled(tool, checkbox.isSelected());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Tool " + tool.name() + 
                                        ": " + checkbox.isSelected());
            });
            toolsPanel.add(checkbox);
            toolCheckboxes.put(tool, checkbox);
        }
        
        // Logging panel
        JPanel loggingPanel = new JPanel(new GridLayout(2, 1)); // Use 2 rows, 1 column layout
        
        // Add logging enable checkbox
        JCheckBox loggingCheckbox = new JCheckBox("Enable Logging", config.getSettings().isLoggingEnabled());
        loggingCheckbox.addActionListener(_ -> {
            config.getSettings().setLoggingEnabled(loggingCheckbox.isSelected());
            config.saveConfig();
            AISecretsDetector.getInstance().logMsg("Configuration updated - Logging: " + config.getSettings().isLoggingEnabled());
            
            if (config.getSettings().isLoggingEnabled()) {
                appendToLog("Logging enabled");
            }
        });
        
        loggingPanel.add(loggingCheckbox);
        
        // Auto-save message (left alignment)
        JPanel autoSavePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel autoSaveLabel = new JLabel("Settings are saved automatically when changed");
        autoSavePanel.add(autoSaveLabel);
        
        // Add Reset Counters button
        JButton resetCountersButton = new JButton("Reset Secret Counters");
        resetCountersButton.setToolTipText("Reset all duplicate detection counters. Use this if too many secrets are being skipped.");
        resetCountersButton.addActionListener(_ -> {
            int result = JOptionPane.showConfirmDialog(
                panel, 
                "This will reset all duplicate secret counters. After reset, you may see duplicate issues reported again. Continue?",
                "Reset Secret Counters",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            
            if (result == JOptionPane.YES_OPTION) {
                resetSecretCounters();
                appendToLog("Secret counters reset successfully");
            }
        });
        
        autoSavePanel.add(Box.createHorizontalStrut(20));
        autoSavePanel.add(resetCountersButton);
        
        // Add Reset to Defaults button
        JButton resetToDefaultsButton = new JButton("Reset to Defaults");
        resetToDefaultsButton.setToolTipText("Reset all settings and patterns to default values.");
        resetToDefaultsButton.addActionListener(_ -> {
            int result = JOptionPane.showConfirmDialog(
                panel, 
                "This will reset all configuration to default values. Continue?",
                "Reset to Defaults",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            
            if (result == JOptionPane.YES_OPTION) {
                config.resetToDefaults();
                appendToLog("Configuration reset to defaults");
                // Refresh the UI by recreating the panel
                refreshUI();
            }
        });
        
        autoSavePanel.add(Box.createHorizontalStrut(10));
        autoSavePanel.add(resetToDefaultsButton);
        
        loggingPanel.add(autoSavePanel);
        
        // Add all panels to the main panel
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(settingsPanel, BorderLayout.NORTH);
        topPanel.add(toolsPanel, BorderLayout.CENTER);
        topPanel.add(loggingPanel, BorderLayout.SOUTH);
        
        panel.add(topPanel, BorderLayout.NORTH);
                
        // log text area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 14));
        JScrollPane logScrollPane = new JScrollPane(logArea);
        
        JButton clearButton = new JButton("Clear Log");
        clearButton.addActionListener(_ -> clearLogs());
        
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Log"));
        logPanel.add(logScrollPane, BorderLayout.CENTER);
        
        JPanel logControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        logControlPanel.add(clearButton);
        logPanel.add(logControlPanel, BorderLayout.NORTH);
        
        panel.add(logPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    private void refreshUI() {
        // This method can be called to refresh the UI after configuration changes
        // For now, we'll just log a message - in a full implementation, you might want to 
        // recreate the entire panel or update individual components
        appendToLog("UI refreshed after configuration reset");
    }

    public void appendToLog(String message) {
        if (logArea != null && config.getSettings().isLoggingEnabled()) {
            SwingUtilities.invokeLater(() -> {
                logArea.append(message + "\n");
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }

    public void clearLogs() {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> logArea.setText(""));
        }
    }
    
    /**
     * Reset all secret counters in the extension
     */
    public void resetSecretCounters() {
        AISecretsDetector detector = AISecretsDetector.getInstance();
        if (detector != null) {
            detector.clearSecretCounters();
            AISecretsDetector.getInstance().logMsg("Secret counters reset");
        }
    }
} 