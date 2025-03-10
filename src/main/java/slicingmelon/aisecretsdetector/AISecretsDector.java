package slicingmelon.aisecretsdetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AISecretsDector implements BurpExtension {
    
    private MontoyaApi api;
    private ExecutorService executorService;
    private ConfigSettings configSettings;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Secrets Detector");
        
        // Initialize configuration and load saved settings
        configSettings = loadConfigSettings(api.persistence().extensionData());
        
        // Initialize worker thread pool
        initializeWorkers();
        
        // Register HTTP handler
        api.http().registerHttpHandler(new SecretsDetectorHttpHandler(api, executorService, configSettings));
        
        // Create and register UI components
        SwingUtilities.invokeLater(() -> {
            JComponent configPanel = createConfigPanel();
            api.userInterface().registerSuiteTab("AI Secrets Detector", configPanel);
        });
        
        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("AI Secrets Detector extension unloading...");
            shutdownWorkers();
        });
        
        api.logging().logToOutput("AI Secrets Detector extension loaded successfully");
    }
    
    private ConfigSettings loadConfigSettings(PersistedObject persistedData) {
        int workers = persistedData.getInteger("workers").orElse(5);
        boolean inScopeOnly = persistedData.getBoolean("in_scope_only").orElse(true);
        
        return new ConfigSettings(workers, inScopeOnly);
    }
    
    private void saveConfigSettings() {
        PersistedObject persistedData = api.persistence().extensionData();
        persistedData.setInteger("workers", configSettings.getWorkers());
        persistedData.setBoolean("in_scope_only", configSettings.isInScopeOnly());
    }
    
    private void initializeWorkers() {
        executorService = Executors.newFixedThreadPool(configSettings.getWorkers());
    }
    
    private void shutdownWorkers() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }
    
    private void updateWorkers() {
        shutdownWorkers();
        initializeWorkers();
    }
    
    private JComponent createConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Create settings panel
        JPanel settingsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);
        
        // Workers setting
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
        c.gridx = 1;
        c.gridy = 0;
        settingsPanel.add(workersSpinner, c);
        
        // In-scope only setting
        JCheckBox inScopeCheckbox = new JCheckBox("In-Scope Requests Only", configSettings.isInScopeOnly());
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 2;
        settingsPanel.add(inScopeCheckbox, c);
        
        // Save button
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> {
            configSettings.setWorkers((Integer) workersSpinner.getValue());
            configSettings.setInScopeOnly(inScopeCheckbox.isSelected());
            
            saveConfigSettings();
            updateWorkers();
            
            api.logging().logToOutput("Configuration saved - Workers: " + configSettings.getWorkers()
                    + ", In-Scope Only: " + configSettings.isInScopeOnly());
        });
        c.gridx = 0;
        c.gridy = 2;
        c.gridwidth = 2;
        settingsPanel.add(saveButton, c);
        
        panel.add(settingsPanel, BorderLayout.NORTH);
        
        // Add results display area
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Detection Results", new JScrollPane(new JTable()));
        panel.add(tabbedPane, BorderLayout.CENTER);
        
        return panel;
    }
}