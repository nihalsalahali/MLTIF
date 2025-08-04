package flare.lsma.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Helper class to push flows to Floodlight/Beacon via REST API.
 */

public class FlowPusher {
    protected static Logger log = LoggerFactory.getLogger(FlowPusher.class);

    private static final String CONTROLLER_URL = "http://127.0.0.1:8080/wm/staticflowpusher/json";

    public void pushFlow(JSONObject flowEntry) {
        try {
            URL url = new URL(CONTROLLER_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            String payload = flowEntry.toString();
            OutputStream os = conn.getOutputStream();
            os.write(payload.getBytes());
            os.flush();

            int responseCode = conn.getResponseCode();
            log.info("➡️ FlowPusher Response: HTTP {}", responseCode);

            conn.disconnect();

        } catch (Exception e) {
            log.error("Error pushing flow: {}", e.getMessage());
        }
    }
}
