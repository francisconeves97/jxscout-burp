import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // Configuration fields
    private String serverHost = "localhost";
    private int serverPort = 3333;
    private boolean filterInScope = true;

    // UI components
    private JPanel mainPanel;
    private JTextField hostField;
    private JTextField portField;
    private JCheckBox inScopeCheckBox;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Set the name of the extension
        callbacks.setExtensionName("jxscout burp");

        // Register the HTTP listener
        callbacks.registerHttpListener(this);

        // Initialize helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Load persisted settings
        loadConfig();

        // Initialize the UI
        initUI();

        // Register the custom tab
        callbacks.addSuiteTab(this);
    }

    private void initUI() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // Add padding to the main panel
        JPanel paddedPanel = new JPanel(new BorderLayout());
        paddedPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Add 10px padding on all sides
        paddedPanel.add(mainPanel, BorderLayout.CENTER);

        // Title and description
        JLabel titleLabel = new JLabel("JXScout Settings");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(titleLabel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Add spacing

        JLabel descriptionLabel = new JLabel("Configure ingestion from Burp to JXScout");
        descriptionLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        descriptionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        mainPanel.add(descriptionLabel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 20))); // Add spacing

        // Configuration fields
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new GridBagLayout());
        configPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        configPanel.setMaximumSize(new Dimension(400, 150)); // Set fixed width

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Host field
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Server Host:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        hostField = new JTextField(serverHost, 20);
        configPanel.add(hostField, gbc);

        // Port field
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Server Port:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        portField = new JTextField(String.valueOf(serverPort), 10);
        configPanel.add(portField, gbc);

        // In-scope checkbox
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.3;
        configPanel.add(new JLabel("Filter In-Scope:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 0.7;
        inScopeCheckBox = new JCheckBox();
        inScopeCheckBox.setSelected(filterInScope);
        configPanel.add(inScopeCheckBox, gbc);

        mainPanel.add(configPanel);

        mainPanel.add(Box.createRigidArea(new Dimension(0, 20))); // Add spacing

        // Save button
        JButton saveButton = new JButton("Save");
        saveButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        saveButton.setMaximumSize(new Dimension(100, 30)); // Set fixed width for button
        saveButton.addActionListener(e -> saveConfig());
        mainPanel.add(saveButton);

        // Set the padded panel as the main panel
        mainPanel = paddedPanel;
    }

    private void saveConfig() {
        try {
            serverHost = hostField.getText();
            serverPort = Integer.parseInt(portField.getText());
            filterInScope = inScopeCheckBox.isSelected();

            // Save settings using Burp's persistence mechanism
            callbacks.saveExtensionSetting("serverHost", serverHost);
            callbacks.saveExtensionSetting("serverPort", String.valueOf(serverPort));
            callbacks.saveExtensionSetting("filterInScope", String.valueOf(filterInScope));

            callbacks.printOutput("Configuration saved: Host=" + serverHost + ", Port=" + serverPort + ", FilterInScope=" + filterInScope);

            // Show success message
            JOptionPane.showMessageDialog(mainPanel, "Settings saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException e) {
            callbacks.printError("Invalid port number");

            // Show error message
            JOptionPane.showMessageDialog(mainPanel, "Invalid port number. Please enter a valid number.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void loadConfig() {
        // Load settings using Burp's persistence mechanism
        String savedHost = callbacks.loadExtensionSetting("serverHost");
        String savedPort = callbacks.loadExtensionSetting("serverPort");
        String savedFilterInScope = callbacks.loadExtensionSetting("filterInScope");

        // Apply loaded settings or use defaults if not set
        serverHost = (savedHost != null) ? savedHost : "localhost";
        serverPort = (savedPort != null) ? Integer.parseInt(savedPort) : 3333;
        filterInScope = (savedFilterInScope != null) ? Boolean.parseBoolean(savedFilterInScope) : true;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        if (!messageIsRequest) {
            byte[] request = message.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(message);
            URL requestUrl = requestInfo.getUrl();

            if (filterInScope && !callbacks.isInScope(requestUrl)) {
                return;
            }

            try {
                byte[] responseData = message.getResponse();
                String rawRequest = new String(request);
                String rawResponse = new String(responseData);

                JSONObject jsonPayload = new JSONObject();
                String urlWithoutPort = requestUrl.getProtocol() + "://" + requestUrl.getHost() + requestUrl.getFile();
                jsonPayload.put("requestUrl", urlWithoutPort);
                jsonPayload.put("request", rawRequest);
                jsonPayload.put("response", rawResponse);

                sendToServer(jsonPayload);
            } catch (Exception e) {
                callbacks.printError("Failed to process message: " + e.getMessage());
            }
        }
    }

    private void sendToServer(JSONObject jsonPayload) {
        try {
            URL url = new URL("http://" + serverHost + ":" + serverPort + "/caido-ingest");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonPayload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
            }

        } catch (IOException e) {
            callbacks.printError("Failed to send data to server: " + e.getMessage());
        }
    }

    @Override
    public String getTabCaption() {
        return "JXScout";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}