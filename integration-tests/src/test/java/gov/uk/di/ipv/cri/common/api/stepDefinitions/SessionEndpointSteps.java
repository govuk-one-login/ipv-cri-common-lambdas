package gov.uk.di.ipv.cri.common.api.stepDefinitions;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import gov.uk.di.ipv.cri.common.api.util.IpvCoreStubUtil;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.http.client.utils.URIBuilder;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SessionEndpointSteps {

    private String sessionRequestBody;
    private HttpResponse<String> response;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String sessionId;

    @Given("user has the user identity in the form of a signed JWT string")
    public void user_has_the_user_identity_in_the_form_of_a_signed_jwt_string()
            throws URISyntaxException, IOException, InterruptedException {
        int experianRowNumber = 681;
        String ipvCoreStubURL = IpvCoreStubUtil.getIPVCoreStubURL();
        String userIdentityJson =
                IpvCoreStubUtil.getClaimsForUser(ipvCoreStubURL, experianRowNumber);
        sessionRequestBody = IpvCoreStubUtil.createRequest(ipvCoreStubURL, userIdentityJson);
    }

    @When("user sends a request to session end point")
    public void user_sends_a_request_to_session_end_point()
            throws URISyntaxException, IOException, InterruptedException {
        var request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(IpvCoreStubUtil.getPrivateAPIEndpoint())
                                        .setPath("/dev/session")
                                        .build())
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(sessionRequestBody))
                        .build();
        response = IpvCoreStubUtil.sendHttpRequest(request);

        Map<String, String> deserializedResponse =
                objectMapper.readValue(response.body(), new TypeReference<>() {});
        sessionId = deserializedResponse.get("session_id");
    }

    @Then("user gets a session-id")
    public void user_gets_a_session_id() {
        assertEquals(201, response.statusCode());
        assertNotNull(response.body());
        assertNotNull(sessionId);
    }
}
