import burp.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

public class BurpExtender implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Set the name of the extension
        callbacks.setExtensionName("jxscout burp");

        // Register the HTTP listener
        callbacks.registerHttpListener(this);
        
        // Initialize helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse message) {
        // Only process responses (you can also handle requests here if needed)
        if (!messageIsRequest) {
            // Extract the raw request from the message
            byte[] request = message.getRequest();

            // Use the correct analyzeRequest method to get the full URL
            IRequestInfo requestInfo = helpers.analyzeRequest(message);  // This method includes full URL details
            URL requestUrl = requestInfo.getUrl();  // Extract URL from request

            // Check if the request is in scope based on the URL
            if (!callbacks.isInScope(requestUrl)) {
                return;
            }

            try {
                // Extract the raw response data
                byte[] responseData = message.getResponse();

                // Convert raw bytes to strings for request and response
                String rawRequest = new String(request);
                String rawResponse = new String(responseData);

                // Create the JSON payload
                JSONObject jsonPayload = new JSONObject();
                // Remove the port from the URL if present
                String urlWithoutPort = requestUrl.getProtocol() + "://" + requestUrl.getHost() + requestUrl.getFile();
                jsonPayload.put("requestUrl", urlWithoutPort);
                jsonPayload.put("request", rawRequest);
                jsonPayload.put("response", rawResponse);

                // Send the data to the external server
                sendToServer(jsonPayload);
            } catch (Exception e) {
                callbacks.printError("Failed to process message: " + e.getMessage());
            }
        }
    }

    private void sendToServer(JSONObject jsonPayload) {
        try {
            // Set the URL of the server to which you want to send the data
            URL url = new URL("http://localhost:3333/caido-ingest");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // Send the request
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonPayload.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Get the response from the server
            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                // Handle server response if needed
            }

        } catch (IOException e) {
            callbacks.printError("Failed to send data to server: " + e.getMessage());
        }
    }
}