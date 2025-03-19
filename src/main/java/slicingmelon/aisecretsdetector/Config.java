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
        
        public ConfigSettings(int workers, boolean inScopeOnly, Set<ToolType> enabledTools, boolean loggingEnabled) {
            this.workers = workers;
            this.inScopeOnly = inScopeOnly;
            this.enabledTools = enabledTools;
            this.loggingEnabled = loggingEnabled;
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
        
        return new ConfigSettings(workers, inScopeOnly, enabledTools, loggingEnabled);
    }
    
    public void saveConfigSettings() {
        PersistedObject persistedData = api.persistence().extensionData();
        persistedData.setInteger("workers", configSettings.getWorkers());
        persistedData.setBoolean("in_scope_only", configSettings.isInScopeOnly());
        persistedData.setBoolean("logging_enabled", configSettings.isLoggingEnabled());
        
        StringBuilder toolsBuilder = new StringBuilder();
        for (ToolType tool : configSettings.getEnabledTools()) {
            if (toolsBuilder.length() > 0) {
                toolsBuilder.append(",");
            }
            toolsBuilder.append(tool.name());
        }
        persistedData.setString("enabled_tools", toolsBuilder.toString());
        
        if (onConfigChangedCallback != null) {
            onConfigChangedCallback.run();
        }
    }
       
    public JComponent createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Settings panel
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // Worker setting
        JLabel workersLabel = new JLabel("Number of Workers:");
        c.gridx = 0;
        c.gridy = 0;
        settingsPanel.add(workersLabel, c);
        
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
        
        c.gridx = 1;
        c.gridy = 0;
        settingsPanel.add(workersSpinner, c);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", configSettings.isInScopeOnly());
        inScopeCheckbox.addActionListener(_ -> {
            configSettings.setInScopeOnly(inScopeCheckbox.isSelected());
            saveConfigSettings();
            api.logging().logToOutput("Configuration updated - In-Scope Only: " + configSettings.isInScopeOnly());
        });
        
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 2;
        settingsPanel.add(inScopeCheckbox, c);
        
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
        
        c.gridx = 0;
        c.gridy = 2;
        c.gridwidth = 2;
        settingsPanel.add(toolsPanel, c);
        
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
        
        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 2;
        settingsPanel.add(loggingCheckbox, c);
        
        JLabel autoSaveLabel = new JLabel("Settings are saved automatically when changed");
        c.gridx = 0;
        c.gridy = 4;
        c.gridwidth = 2;
        settingsPanel.add(autoSaveLabel, c);
        
        panel.add(settingsPanel, BorderLayout.NORTH);
                
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