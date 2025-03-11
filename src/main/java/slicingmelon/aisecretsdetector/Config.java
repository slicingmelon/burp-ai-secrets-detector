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
    
    public static class ConfigSettings {
        private int workers;
        private boolean inScopeOnly;
        private Set<ToolType> enabledTools;
        
        public ConfigSettings(int workers, boolean inScopeOnly, Set<ToolType> enabledTools) {
            this.workers = workers;
            this.inScopeOnly = inScopeOnly;
            this.enabledTools = enabledTools;
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
    }
    
    public Config(MontoyaApi api, Runnable onConfigChangedCallback) {
        this.api = api;
        this.onConfigChangedCallback = onConfigChangedCallback;
        
        // Load saved settings
        this.configSettings = loadConfigSettings(api.persistence().extensionData());
    }
    
    public ConfigSettings getConfigSettings() {
        return configSettings;
    }
    
    public ConfigSettings loadConfigSettings(PersistedObject persistedData) {
        // Fix using null check approach
        Integer workersValue = persistedData.getInteger("workers");
        int workers = (workersValue != null) ? workersValue : 5;
        
        Boolean inScopeOnlyValue = persistedData.getBoolean("in_scope_only");
        boolean inScopeOnly = (inScopeOnlyValue != null) ? inScopeOnlyValue : true;
        
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
        
        return new ConfigSettings(workers, inScopeOnly, enabledTools);
    }
    
    public void saveConfigSettings() {
        PersistedObject persistedData = api.persistence().extensionData();
        persistedData.setInteger("workers", configSettings.getWorkers());
        persistedData.setBoolean("in_scope_only", configSettings.isInScopeOnly());
        
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
        
        JLabel autoSaveLabel = new JLabel("Settings are saved automatically when changed");
        c.gridx = 0;
        c.gridy = 3;
        c.gridwidth = 2;
        settingsPanel.add(autoSaveLabel, c);
        
        panel.add(settingsPanel, BorderLayout.NORTH);
        
        // Add results display area (in the future mby)
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Detection Results", new JScrollPane(new JTable()));
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
}