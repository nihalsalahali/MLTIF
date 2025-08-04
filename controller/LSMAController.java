package flare.lsma.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.json.JSONObject;

/**
 * FLARE LSMA Controller
 * ----------------------
 * For Java-based SDN controllers: Beacon, Floodlight, OpenDaylight.
 * Exposes REST API to receive alerts and push mitigation policies.
 */

@Path("/flare")
public class LSMAController {

    protected static Logger log = LoggerFactory.getLogger(LSMAController.class);

    // Example: GET test
    @GET
    @Path("/ping")
    public String ping() {
        return "FLARE LSMA Controller is alive!";
    }

    // POST: Receive alert JSON
    @POST
    @Path("/alert")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response receiveAlert(String alertJson) {
        try {
            JSONObject alert = new JSONObject(alertJson);

            String alertId = alert.getString("alert_id");
            double confidence = alert.getDouble("classifier_confidence");
            boolean frag = alert.getJSONObject("flags").getBoolean("FRAG");
            boolean rst = alert.getJSONObject("flags").getBoolean("RST");

            log.info("✅ Received Alert: {}", alertId);

            // Example logic: install mitigation rule if risky
            if (confidence > 0.9 || frag || rst) {
                installMitigationPolicy(alert);
            }

            return Response.ok().entity("Alert processed: " + alertId).build();

        } catch (Exception e) {
            log.error("Error parsing alert JSON: {}", e.getMessage());
            return Response.status(400).entity("Invalid JSON").build();
        }
    }

    private void installMitigationPolicy(JSONObject alert) {
        // Example: Install drop rule or rate limit on suspicious traffic
        String srcIp = alert.getString("source_ip");
        String dstIp = alert.getString("destination_ip");

        log.info("🚨 Installing mitigation for src: {}, dst: {}", srcIp, dstIp);

        // If you are using Floodlight, call FlowPusher REST API:
        FlowPusher push = new FlowPusher();
        JSONObject flow = new JSONObject();
        flow.put("switch", "00:00:00:00:00:00:00:01");
        flow.put("name", "block_bad_traffic");
        flow.put("priority", "32768");
        flow.put("eth_type", "0x0800");
        flow.put("ipv4_src", srcIp);
        flow.put("ipv4_dst", dstIp);
        flow.put("active", "true");
        flow.put("actions", "drop");

        push.pushFlow(flow);
    }
}
