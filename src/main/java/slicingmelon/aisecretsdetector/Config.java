/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.core.ToolType;
import javax.swing.*;
import java.awt.*;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

public class Config {
    private MontoyaApi api;
    private ConfigSettings configSettings;
    private Runnable onConfigChangedCallback;
    private JTextArea logArea;

    private static Config instance;
    
    public static class ConfigSettings {
        private int workers;
        private boolean inScopeOnly;
        private Set<ToolType> enabledTools;
        private boolean loggingEnabled;
        private boolean randomnessAlgorithmEnabled;
        private int genericSecretMinLength;
        private int genericSecretMaxLength;
        
        public ConfigSettings(int workers, boolean inScopeOnly, Set<ToolType> enabledTools, boolean loggingEnabled,
                             boolean randomnessAlgorithmEnabled, int genericSecretMinLength, int genericSecretMaxLength) {
            this.workers = workers;
            this.inScopeOnly = inScopeOnly;
            this.enabledTools = enabledTools;
            this.loggingEnabled = loggingEnabled;
            this.randomnessAlgorithmEnabled = randomnessAlgorithmEnabled;
            this.genericSecretMinLength = genericSecretMinLength;
            this.genericSecretMaxLength = genericSecretMaxLength;
        }
        
        public int getWorkers() {
            return workers;
        }
        
        public void setWorkers(int workers) {
            this.workers = workers;
        }
        
        public boolean isInScopeOnly() {
            return inScopeOnly;
        }
        
        public void setInScopeOnly(boolean inScopeOnly) {
            this.inScopeOnly = inScopeOnly;
        }
        
        public Set<ToolType> getEnabledTools() {
            return enabledTools;
        }
        
        public void setEnabledTools(Set<ToolType> enabledTools) {
            this.enabledTools = enabledTools;
        }
        
        public boolean isToolEnabled(ToolType toolType) {
            return enabledTools.contains(toolType);
        }
        
        public void setToolEnabled(ToolType toolType, boolean enabled) {
            if (enabled) {
                enabledTools.add(toolType);
            } else {
                enabledTools.remove(toolType);
            }
        }

        public boolean isLoggingEnabled() {
            return loggingEnabled;
        }
        
        public void setLoggingEnabled(boolean loggingEnabled) {
            this.loggingEnabled = loggingEnabled;
        }
        
        public boolean isRandomnessAlgorithmEnabled() {
            return randomnessAlgorithmEnabled;
        }
        
        public void setRandomnessAlgorithmEnabled(boolean randomnessAlgorithmEnabled) {
            this.randomnessAlgorithmEnabled = randomnessAlgorithmEnabled;
        }
        
        public int getGenericSecretMinLength() {
            return genericSecretMinLength;
        }
        
        public void setGenericSecretMinLength(int genericSecretMinLength) {
            this.genericSecretMinLength = Math.max(4, genericSecretMinLength);
        }
        
        public int getGenericSecretMaxLength() {
            return genericSecretMaxLength;
        }
        
        public void setGenericSecretMaxLength(int genericSecretMaxLength) {
            this.genericSecretMaxLength = Math.min(128, genericSecretMaxLength);
        }
    }
    
    public static Config getInstance() {
        return instance;
    }

    public Config(MontoyaApi api, Runnable onConfigChangedCallback) {
        this.api = api;
        this.onConfigChangedCallback = onConfigChangedCallback;
        
        // Load saved settings
        this.configSettings = loadConfigSettings(api.persistence().extensionData());
        
        // Store instance for singleton access
        instance = this;
    }
    
    public ConfigSettings getConfigSettings() {
        return configSettings;
    }
    
    public ConfigSettings loadConfigSettings(PersistedObject persistedData) {
        // Fix using null check approach
        Integer workersValue = persistedData.getInteger("workers");
        int workers = (workersValue != null) ? workersValue : 10;
        
        Boolean inScopeOnlyValue = persistedData.getBoolean("in_scope_only");
        boolean inScopeOnly = (inScopeOnlyValue != null) ? inScopeOnlyValue : true;

        Boolean loggingEnabledValue = persistedData.getBoolean("logging_enabled");
        boolean loggingEnabled = (loggingEnabledValue != null) ? loggingEnabledValue : false;
        
        Boolean randomnessAlgorithmEnabledValue = persistedData.getBoolean("randomness_algorithm_enabled");
        boolean randomnessAlgorithmEnabled = (randomnessAlgorithmEnabledValue != null) ? randomnessAlgorithmEnabledValue : true;
        
        Integer genericSecretMinLengthValue = persistedData.getInteger("generic_secret_min_length");
        int genericSecretMinLength = (genericSecretMinLengthValue != null) ? 
                                    Math.max(4, genericSecretMinLengthValue) : 15;
        
        Integer genericSecretMaxLengthValue = persistedData.getInteger("generic_secret_max_length");
        int genericSecretMaxLength = (genericSecretMaxLengthValue != null) ? 
                                    Math.min(128, genericSecretMaxLengthValue) : 80;
        
        // Initialize with default tool settings
        Set<ToolType> enabledTools = new HashSet<>();
        enabledTools.add(ToolType.TARGET);
        enabledTools.add(ToolType.PROXY);
        enabledTools.add(ToolType.SCANNER);
        enabledTools.add(ToolType.EXTENSIONS);
        
        // Load saved tool settings if available
        String toolsConfig = persistedData.getString("enabled_tools");
        if (toolsConfig != null && !toolsConfig.isEmpty()) {
            enabledTools.clear();
            for (String tool : toolsConfig.split(",")) {
                try {
                    enabledTools.add(ToolType.valueOf(tool));
                } catch (IllegalArgumentException e) {
                    api.logging().logToError("Invalid tool type in config: " + tool);
                }
            }
        }
        
        return new ConfigSettings(workers, inScopeOnly, enabledTools, loggingEnabled, 
                                 randomnessAlgorithmEnabled, genericSecretMinLength, genericSecretMaxLength);
    }
    
    public void saveConfigSettings() {
        PersistedObject persistedData = api.persistence().extensionData();
        persistedData.setInteger("workers", configSettings.getWorkers());
        persistedData.setBoolean("in_scope_only", configSettings.isInScopeOnly());
        persistedData.setBoolean("logging_enabled", configSettings.isLoggingEnabled());
        persistedData.setBoolean("randomness_algorithm_enabled", configSettings.isRandomnessAlgorithmEnabled());
        persistedData.setInteger("generic_secret_min_length", configSettings.getGenericSecretMinLength());
        persistedData.setInteger("generic_secret_max_length", configSettings.getGenericSecretMaxLength());
        
        StringBuilder toolsBuilder = new StringBuilder();
        for (ToolType tool : configSettings.getEnabledTools()) {
            if (toolsBuilder.length() > 0) {
                toolsBuilder.append(",");
            }
            toolsBuilder.append(tool.name());
        }
        persistedData.setString("enabled_tools", toolsBuilder.toString());
        
        // Update SecretScannerUtils settings
        SecretScannerUtils.setGenericSecretMinLength(configSettings.getGenericSecretMinLength());
        SecretScannerUtils.setGenericSecretMaxLength(configSettings.getGenericSecretMaxLength());
        SecretScannerUtils.setRandomnessAlgorithmEnabled(configSettings.isRandomnessAlgorithmEnabled());
        
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
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
        
        // Worker setting
        JLabel workersLabel = new JLabel("Number of Workers:");
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 0;
        leftPanel.add(workersLabel, leftConstraints);
        
        SpinnerNumberModel workersModel = new SpinnerNumberModel(
                configSettings.getWorkers(),
                1,
                50,
                1
        );
        JSpinner workersSpinner = new JSpinner(workersModel);
        workersSpinner.addChangeListener(_ -> {
            configSettings.setWorkers((Integer) workersSpinner.getValue());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - Workers: " + configSettings.getWorkers());
        });
        
        leftConstraints.gridx = 1;
        leftConstraints.gridy = 0;
        leftPanel.add(workersSpinner, leftConstraints);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", configSettings.isInScopeOnly());
        inScopeCheckbox.addActionListener(_ -> {
            configSettings.setInScopeOnly(inScopeCheckbox.isSelected());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - In-Scope Only: " + configSettings.isInScopeOnly());
        });
        
        leftConstraints.gridx = 0;
        leftConstraints.gridy = 1;
        leftConstraints.gridwidth = 2;
        leftPanel.add(inScopeCheckbox, leftConstraints);
        
        // Right panel - for randomness algorithm settings
        JPanel rightPanel = new JPanel(new GridBagLayout());
        GridBagConstraints rightConstraints = new GridBagConstraints();
        rightConstraints.fill = GridBagConstraints.HORIZONTAL;
        rightConstraints.insets = new Insets(5, 5, 5, 5);
        
        // Randomness Algorithm Enable
        JCheckBox randomnessCheckbox = new JCheckBox("Enable Randomness Algorithm Detection", 
                                                   configSettings.isRandomnessAlgorithmEnabled());
        randomnessCheckbox.addActionListener(_ -> {
            configSettings.setRandomnessAlgorithmEnabled(randomnessCheckbox.isSelected());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - Randomness Algorithm: " + 
                                     configSettings.isRandomnessAlgorithmEnabled());
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
        rightPanel.add(minLengthLabel, rightConstraints);
        
        SpinnerNumberModel minLengthModel = new SpinnerNumberModel(
                configSettings.getGenericSecretMinLength(),
                4,   // Minimum allowed value
                128, // Maximum allowed value for min length
                1
        );
        JSpinner minLengthSpinner = new JSpinner(minLengthModel);
        minLengthSpinner.addChangeListener(_ -> {
            configSettings.setGenericSecretMinLength((Integer) minLengthSpinner.getValue());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - Min Secret Length: " + 
                                     configSettings.getGenericSecretMinLength());
        });
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 1;
        rightPanel.add(minLengthSpinner, rightConstraints);
        
        // Max Length setting
        JLabel maxLengthLabel = new JLabel("Generic Secret Max Length (Randomness Algorithm):");
        rightConstraints.gridx = 0;
        rightConstraints.gridy = 2;
        rightPanel.add(maxLengthLabel, rightConstraints);
        
        SpinnerNumberModel maxLengthModel = new SpinnerNumberModel(
                configSettings.getGenericSecretMaxLength(),
                4,   // Minimum allowed value for max length
                128, // Maximum allowed value
                1
        );
        JSpinner maxLengthSpinner = new JSpinner(maxLengthModel);
        maxLengthSpinner.addChangeListener(_ -> {
            configSettings.setGenericSecretMaxLength((Integer) maxLengthSpinner.getValue());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - Max Secret Length: " + 
                                     configSettings.getGenericSecretMaxLength());
        });
        
        rightConstraints.gridx = 1;
        rightConstraints.gridy = 2;
        rightPanel.add(maxLengthSpinner, rightConstraints);
        
        // Add left and right panels to the settings panel
        settingsPanel.add(leftPanel);
        settingsPanel.add(rightPanel);
        
        // Tool source settings
        JPanel toolsPanel = new JPanel();
        toolsPanel.setBorder(BorderFactory.createTitledBorder("Process Messages from Tools:"));
        toolsPanel.setLayout(new GridLayout(0, 2));
        
        Map<ToolType, JCheckBox> toolCheckboxes = new HashMap<>();
        
        ToolType[] relevantTools = {
            ToolType.TARGET, ToolType.PROXY, ToolType.SCANNER, 
            ToolType.EXTENSIONS, ToolType.REPEATER, ToolType.INTRUDER
        };
        
        for (ToolType tool : relevantTools) {
            JCheckBox checkbox = new JCheckBox(tool.name(), configSettings.isToolEnabled(tool));
            checkbox.addActionListener(_ -> {
                configSettings.setToolEnabled(tool, checkbox.isSelected());
                saveConfigSettings();
                api.logging().logToOutput("Configuration updated - Tool " + tool.name() + 
                                        ": " + checkbox.isSelected());
            });
            toolsPanel.add(checkbox);
            toolCheckboxes.put(tool, checkbox);
        }
        
        // Logging panel
        JPanel loggingPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        // Add logging enable checkbox
        JCheckBox loggingCheckbox = new JCheckBox("Enable Logging", configSettings.isLoggingEnabled());
        loggingCheckbox.addActionListener(_ -> {
            configSettings.setLoggingEnabled(loggingCheckbox.isSelected());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - Logging: " + configSettings.isLoggingEnabled());
            
            if (configSettings.isLoggingEnabled()) {
                appendToLog("Logging enabled");
            }
        });
        
        loggingPanel.add(loggingCheckbox);
        
        JLabel autoSaveLabel = new JLabel("Settings are saved automatically when changed");
        loggingPanel.add(autoSaveLabel);
        
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

    public void appendToLog(String message) {
        if (logArea != null && configSettings.isLoggingEnabled()) {
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
}