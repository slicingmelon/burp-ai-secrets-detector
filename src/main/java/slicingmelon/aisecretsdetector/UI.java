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
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class UI {
    private MontoyaApi api;
    private Config config;
    private JTextArea logArea;
    private JTextArea errorLogArea;
    private static UI instance;
    private static final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
    
    public static UI getInstance() {
        return instance;
    }

    public UI(MontoyaApi api) {
        this.api = api;
        this.config = Config.getInstance();
        
        // Ensure config is never null
        if (this.config == null) {
            // This should not happen with the improved Config.getInstance(), but just in case
            this.config = Config.initialize(api, null);
        }
        
        instance = this;
    }
    
    public JComponent createConfigPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Create tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Config tab
        JPanel configPanel = createConfigTab();
        tabbedPane.addTab("Config", configPanel);
        
        // Log tab
        JPanel logPanel = createLogTab();
        tabbedPane.addTab("Log", logPanel);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        return mainPanel;
    }
    
    private JPanel createConfigTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Settings panel - now uses a split layout
        JPanel settingsPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        
        // Left panel - for worker settings and basic configuration
        JPanel leftPanel = new JPanel(new GridBagLayout());
        GridBagConstraints leftConstraints = new GridBagConstraints();
        leftConstraints.fill = GridBagConstraints.HORIZONTAL;
        leftConstraints.insets = new Insets(5, 5, 5, 5);
        leftConstraints.anchor = GridBagConstraints.WEST;
        
        // Worker setting
        JLabel workersLabel = new JLabel("Number of Workers:");
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 0;
        leftConstraints.weightx = 0.0;
        leftPanel.add(workersLabel, leftConstraints);
        
        SpinnerNumberModel workersModel = new SpinnerNumberModel(
                config != null ? config.getSettings().getWorkers() : 15,
                1,
                50,
                1
        );
        JSpinner workersSpinner = new JSpinner(workersModel);
        
        JComponent editor = workersSpinner.getEditor();
        Dimension prefSize = new Dimension(60, editor.getPreferredSize().height);
        editor.setPreferredSize(prefSize);
        workersSpinner.setMaximumSize(new Dimension(60, workersSpinner.getPreferredSize().height));
        
        JPanel spinnerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        spinnerPanel.setOpaque(false);
        spinnerPanel.add(workersSpinner);
        
        workersSpinner.addChangeListener(e -> {
            if (config != null) {
                config.getSettings().setWorkers((Integer) workersSpinner.getValue());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Workers: " + config.getSettings().getWorkers());
            }
        });
        
        leftConstraints.gridx = 1;
        leftConstraints.gridy = 0;
        leftConstraints.weightx = 0.0;
        leftPanel.add(spinnerPanel, leftConstraints);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", 
                config != null ? config.getSettings().isInScopeOnly() : true);
        inScopeCheckbox.addActionListener(e -> {
            if (config != null) {
                config.getSettings().setInScopeOnly(inScopeCheckbox.isSelected());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - In-Scope Only: " + config.getSettings().isInScopeOnly());
            }
        });
        
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 1;
        leftConstraints.gridwidth = 2;
        leftConstraints.weightx = 1.0;
        leftPanel.add(inScopeCheckbox, leftConstraints);
        
        // Enable logging setting
        JCheckBox loggingCheckbox = new JCheckBox("Enable Logging", 
                config != null ? config.getSettings().isLoggingEnabled() : false);
        loggingCheckbox.addActionListener(e -> {
            if (config != null) {
                config.getSettings().setLoggingEnabled(loggingCheckbox.isSelected());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Logging: " + config.getSettings().isLoggingEnabled());
            }
        });
        
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 2;
        leftConstraints.gridwidth = 2;
        leftConstraints.weightx = 1.0;
        leftPanel.add(loggingCheckbox, leftConstraints);
        
        // Right panel - for randomness algorithm settings
        JPanel rightPanel = new JPanel(new GridBagLayout());
        GridBagConstraints rightConstraints = new GridBagConstraints();
        rightConstraints.fill = GridBagConstraints.HORIZONTAL;
        rightConstraints.insets = new Insets(5, 5, 5, 5);
        rightConstraints.anchor = GridBagConstraints.WEST;
        
        // Randomness Algorithm Enable
        JCheckBox randomnessCheckbox = new JCheckBox("Enable Randomness Algorithm Detection", 
                config != null ? config.getSettings().isRandomnessAlgorithmEnabled() : true);
        randomnessCheckbox.addActionListener(e -> {
            if (config != null) {
                config.getSettings().setRandomnessAlgorithmEnabled(randomnessCheckbox.isSelected());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Randomness Algorithm: " +
                        config.getSettings().isRandomnessAlgorithmEnabled());
            }
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
        rightConstraints.weightx = 0.0;
        rightPanel.add(minLengthLabel, rightConstraints);
        
        SpinnerNumberModel minLengthModel = new SpinnerNumberModel(
                config != null ? config.getSettings().getGenericSecretMinLength() : 15,
                8,
                128,
                1
        );
        JSpinner minLengthSpinner = new JSpinner(minLengthModel);
        minLengthSpinner.addChangeListener(e -> {
            if (config != null) {
                config.getSettings().setGenericSecretMinLength((Integer) minLengthSpinner.getValue());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Min Secret Length: " +
                        config.getSettings().getGenericSecretMinLength());
            }
        });
        
        JComponent minEditor = minLengthSpinner.getEditor();
        Dimension minPrefSize = new Dimension(60, minEditor.getPreferredSize().height);
        minEditor.setPreferredSize(minPrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 1;
        rightConstraints.weightx = 0.0;
        rightPanel.add(minLengthSpinner, rightConstraints);
        
        // Max Length setting
        JLabel maxLengthLabel = new JLabel("Generic Secret Max Length (Randomness Algorithm):");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 2;
        rightConstraints.weightx = 0.0;
        rightPanel.add(maxLengthLabel, rightConstraints);
        
        SpinnerNumberModel maxLengthModel = new SpinnerNumberModel(
                config != null ? config.getSettings().getGenericSecretMaxLength() : 80,
                8,
                128,
                1
        );
        JSpinner maxLengthSpinner = new JSpinner(maxLengthModel);
        maxLengthSpinner.addChangeListener(e -> {
            if (config != null) {
                config.getSettings().setGenericSecretMaxLength((Integer) maxLengthSpinner.getValue());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Max Secret Length: " +
                        config.getSettings().getGenericSecretMaxLength());
            }
        });
        
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
                config != null ? config.getSettings().getDuplicateThreshold() : 5,
                1,
                50,
                1
        );
        JSpinner duplicateThresholdSpinner = new JSpinner(duplicateThresholdModel);
        duplicateThresholdSpinner.addChangeListener(e -> {
            if (config != null) {
                config.getSettings().setDuplicateThreshold((Integer) duplicateThresholdSpinner.getValue());
                config.saveConfig();
                AISecretsDetector.getInstance().logMsg("Configuration updated - Duplicate Threshold: " +
                        config.getSettings().getDuplicateThreshold());
            }
        });
        
        JComponent duplicateEditor = duplicateThresholdSpinner.getEditor();
        Dimension duplicatePrefSize = new Dimension(60, duplicateEditor.getPreferredSize().height);
        duplicateEditor.setPreferredSize(duplicatePrefSize);
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 3;
        rightConstraints.weightx = 0.0;
        rightPanel.add(duplicateThresholdSpinner, rightConstraints);
        
        // Add left and right panels to settings panel
        settingsPanel.add(leftPanel);
        settingsPanel.add(rightPanel);
        
        // Tool selection panel
        JPanel toolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolPanel.setBorder(new TitledBorder("Process Messages from Tools:"));
        
        // Tool checkboxes
        Map<ToolType, JCheckBox> toolCheckboxes = new HashMap<>();
        ToolType[] tools = {ToolType.TARGET, ToolType.PROXY, ToolType.SCANNER, ToolType.EXTENSIONS, ToolType.REPEATER, ToolType.INTRUDER};
        
        for (ToolType tool : tools) {
            JCheckBox toolCheckbox = new JCheckBox(tool.name(), 
                    config != null ? config.getSettings().isToolEnabled(tool) : false);
            toolCheckbox.addActionListener(e -> {
                if (config != null) {
                    config.getSettings().setToolEnabled(tool, toolCheckbox.isSelected());
                    config.saveConfig();
                    AISecretsDetector.getInstance().logMsg("Configuration updated - Tool " + tool.name() + ": " + toolCheckbox.isSelected());
                }
            });
            toolCheckboxes.put(tool, toolCheckbox);
            toolPanel.add(toolCheckbox);
        }
        
        // Config Info panel
        JPanel configInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        configInfoPanel.setBorder(new TitledBorder("Configuration Information:"));
        
        // Config file location info
        JLabel configLocationLabel = new JLabel("Config Storage: ");
        configLocationLabel.setFont(configLocationLabel.getFont().deriveFont(Font.BOLD));
        configInfoPanel.add(configLocationLabel);
        
        JLabel configLocationValue = new JLabel(getConfigLocationInfo());
        configLocationValue.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        configInfoPanel.add(configLocationValue);
        
        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.setBorder(new TitledBorder("Actions:"));
        
        JButton resetCountersButton = new JButton("Reset Secret Counters");
        resetCountersButton.addActionListener(e -> resetSecretCounters());
        buttonPanel.add(resetCountersButton);
        
        JButton resetDefaultsButton = new JButton("Reset to Defaults");
        resetDefaultsButton.addActionListener(e -> resetToDefaults());
        buttonPanel.add(resetDefaultsButton);
        
        JButton exportConfigButton = new JButton("Export Config to File");
        exportConfigButton.addActionListener(e -> exportConfigToFile());
        buttonPanel.add(exportConfigButton);
        
        JButton importConfigButton = new JButton("Import Config from File");
        importConfigButton.addActionListener(e -> importConfigFromFile());
        buttonPanel.add(importConfigButton);
        
        // Create a combined bottom panel for config info and buttons
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(configInfoPanel, BorderLayout.NORTH);
        bottomPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Add all panels to main config panel
        panel.add(settingsPanel, BorderLayout.NORTH);
        panel.add(toolPanel, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createLogTab() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create split pane for normal and error logs
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5); // Equal distribution
        
        // Left panel - Normal logs
        JPanel normalLogPanel = new JPanel(new BorderLayout());
        normalLogPanel.setBorder(new TitledBorder("Normal Logs"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        logScrollPane.setPreferredSize(new Dimension(400, 300));
        
        normalLogPanel.add(logScrollPane, BorderLayout.CENTER);
        
        // Right panel - Error logs
        JPanel errorLogPanel = new JPanel(new BorderLayout());
        errorLogPanel.setBorder(new TitledBorder("Error Logs"));
        
        errorLogArea = new JTextArea();
        errorLogArea.setEditable(false);
        errorLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        errorLogArea.setForeground(Color.RED);
        
        JScrollPane errorLogScrollPane = new JScrollPane(errorLogArea);
        errorLogScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        errorLogScrollPane.setPreferredSize(new Dimension(400, 300));
        
        errorLogPanel.add(errorLogScrollPane, BorderLayout.CENTER);
        
        // Add panels to split pane
        splitPane.setLeftComponent(normalLogPanel);
        splitPane.setRightComponent(errorLogPanel);
        
        // Button panel for log actions
        JPanel logButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearLogButton = new JButton("Clear Normal Log");
        clearLogButton.addActionListener(e -> clearLogs());
        logButtonPanel.add(clearLogButton);
        
        JButton clearErrorLogButton = new JButton("Clear Error Log");
        clearErrorLogButton.addActionListener(e -> clearErrorLogs());
        logButtonPanel.add(clearErrorLogButton);
        
        JButton clearAllLogsButton = new JButton("Clear All Logs");
        clearAllLogsButton.addActionListener(e -> {
            clearLogs();
            clearErrorLogs();
        });
        logButtonPanel.add(clearAllLogsButton);
        
        // Add components to main panel
        panel.add(splitPane, BorderLayout.CENTER);
        panel.add(logButtonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private void refreshUI() {
        // This method can be used to refresh UI components if needed
        SwingUtilities.invokeLater(() -> {
            // Update any UI components that need refreshing
        });
    }
    
    public void appendToLog(String message) {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                String timestamp = LocalDateTime.now().format(timeFormatter);
                logArea.append("[" + timestamp + "] " + message + "\n");
            });
        }
    }
    
    public void appendToErrorLog(String message) {
        if (errorLogArea != null) {
            SwingUtilities.invokeLater(() -> {
                String timestamp = LocalDateTime.now().format(timeFormatter);
                errorLogArea.append("[" + timestamp + "] " + message + "\n");
            });
        }
    }
    
    public void clearLogs() {
        if (logArea != null) {
            SwingUtilities.invokeLater(() -> {
                logArea.setText("");
                appendToLog("Normal log cleared");
            });
        }
    }
    
    public void clearErrorLogs() {
        if (errorLogArea != null) {
            SwingUtilities.invokeLater(() -> {
                errorLogArea.setText("");
                appendToErrorLog("Error log cleared");
            });
        }
    }
    
    public void resetSecretCounters() {
        if (AISecretsDetector.getInstance() != null) {
            AISecretsDetector.getInstance().clearSecretCounters();
            appendToLog("Secret counters have been reset");
        }
    }
    
    private void resetToDefaults() {
        if (config != null) {
            config.resetToDefaults();
            appendToLog("Configuration reset to defaults");
        }
    }
    
    private void reloadConfig() {
        if (config != null) {
            try {
                // Force reload the configuration from persistence
                config.reloadConfig();
                appendToLog("Configuration reloaded from persisted settings");
                
                // This will trigger the callback to update workers and scanner
                AISecretsDetector.getInstance().logMsg("Configuration manually reloaded - patterns and workers updated");
            } catch (Exception e) {
                appendToErrorLog("Failed to reload configuration: " + e.getMessage());
            }
        }
    }
    
    private String getConfigLocationInfo() {
        try {
            StringBuilder info = new StringBuilder();
            
            // Primary storage location
            info.append("Primary: Burp Extension Data Storage (persistent)");
            
            // Check if we have persisted config
            if (api != null) {
                try {
                    String savedConfig = api.persistence().extensionData().getString("config_toml");
                    if (savedConfig != null && !savedConfig.isEmpty()) {
                        info.append(" [ACTIVE]");
                    } else {
                        info.append(" [EMPTY - using defaults]");
                    }
                } catch (Exception e) {
                    info.append(" [ERROR]");
                }
            } else {
                info.append(" [NO API]");
            }
            
            // External config file path
            if (config != null) {
                try {
                    String configPath = config.getDefaultConfigFilePath();
                    // Truncate long paths for display
                    String displayPath = configPath.length() > 60 ? 
                        "..." + configPath.substring(configPath.length() - 57) : configPath;
                    
                    info.append(" | External: ");
                    info.append(displayPath);
                    if (config.hasExportedConfigFile()) {
                        info.append(" [EXISTS]");
                    } else {
                        info.append(" [NOT FOUND]");
                    }
                } catch (Exception e) {
                    info.append(" | External: [ERROR: " + e.getMessage() + "]");
                }
            } else {
                info.append(" | External: [CONFIG NOT AVAILABLE]");
            }
            
            return info.toString();
        } catch (Exception e) {
            return "Config storage information unavailable: " + e.getMessage();
        }
    }
    
    private void exportConfigToFile() {
        if (config == null) {
            appendToErrorLog("Config not available for export");
            return;
        }
        
        try {
            String defaultPath = config.getDefaultConfigFilePath();
            String filePath = JOptionPane.showInputDialog(
                null,
                "Enter the path to save the config file:\n\nDefault location: " + defaultPath + "\n\n(Leave empty to use default)",
                "Export Config to File",
                JOptionPane.QUESTION_MESSAGE
            );
            
            if (filePath != null && !filePath.trim().isEmpty()) {
                // Use default path if user just presses OK with empty input
                if (filePath.trim().equals("")) {
                    filePath = defaultPath;
                }
                
                config.exportConfigToFile(filePath);
                appendToLog("Configuration exported to: " + filePath);
                
                // Refresh the UI to show updated status
                refreshUI();
                
                JOptionPane.showMessageDialog(
                    null,
                    "Configuration exported successfully!\n\nFile: " + filePath + "\n\nYou can now edit this file with any text editor and use 'Import Config from File' to reload.",
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        } catch (Exception e) {
            String errorMsg = "Failed to export config: " + e.getMessage();
            appendToErrorLog(errorMsg);
            JOptionPane.showMessageDialog(
                null,
                errorMsg,
                "Export Failed",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
    
    private void importConfigFromFile() {
        if (config == null) {
            appendToErrorLog("Config not available for import");
            return;
        }
        
        try {
            String defaultPath = config.getDefaultConfigFilePath();
            String filePath = JOptionPane.showInputDialog(
                null,
                "Enter the path to the config file to import:\n\nDefault location: " + defaultPath + "\n\n(Leave empty to use default)",
                "Import Config from File",
                JOptionPane.QUESTION_MESSAGE
            );
            
            if (filePath != null && !filePath.trim().isEmpty()) {
                // Use default path if user just presses OK with empty input
                if (filePath.trim().equals("")) {
                    filePath = defaultPath;
                }
                
                config.importConfigFromFile(filePath);
                appendToLog("Configuration imported from: " + filePath);
                
                // Refresh the UI to show updated settings
                refreshUI();
                
                JOptionPane.showMessageDialog(
                    null,
                    "Configuration imported successfully!\n\nFile: " + filePath + "\n\nSettings have been updated and saved to Burp persistence.",
                    "Import Successful",
                    JOptionPane.INFORMATION_MESSAGE
                );
            }
        } catch (Exception e) {
            String errorMsg = "Failed to import config: " + e.getMessage();
            appendToErrorLog(errorMsg);
            JOptionPane.showMessageDialog(
                null,
                errorMsg,
                "Import Failed",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
} 