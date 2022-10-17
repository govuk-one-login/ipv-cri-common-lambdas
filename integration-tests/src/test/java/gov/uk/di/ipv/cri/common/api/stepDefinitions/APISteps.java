package gov.uk.di.ipv.cri.common.api.stepDefinitions;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import gov.uk.di.ipv.cri.common.api.util.IpvCoreStubUtil;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.http.HttpResponse;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class APISteps {

    private final String ENVIRONMENT = "/dev"; // dev, build, staging, integration
    private final String DEV_SESSION_URI = ENVIRONMENT + "/session";
    private final String DEV_AUTHORIZATION_URI = ENVIRONMENT + "/authorization";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String sessionRequestBody;
    private String sessionId;
    private HttpResponse<String> response;
    private Map<String, String> responseBodyMap;

    @Given("authorization JAR for test user {int}")
    public void setAuthorizationJARForTestUser(int rowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String userIdentityJson = IpvCoreStubUtil.getClaimsForUser(rowNumber);
        sessionRequestBody = IpvCoreStubUtil.sendCreateSessionRequest(userIdentityJson);
    }

    @When("user sends a request to session API")
    public void user_sends_a_request_to_session_api()
            throws URISyntaxException, IOException, InterruptedException {
        response = IpvCoreStubUtil.sendSessionRequest(DEV_SESSION_URI, sessionRequestBody);
        responseBodyMap = objectMapper.readValue(response.body(), new TypeReference<>() {});
    }

    @Then("user gets a session id")
    public void user_gets_a_session_id() {
        assertEquals(201, response.statusCode());
        assertNotNull(responseBodyMap.get("session_id"));
        sessionId = responseBodyMap.get("session_id");
    }

    @When("user sends an empty request to session end point")
    public void user_sends_an_empty_request_to_session_end_point()
            throws URISyntaxException, IOException, InterruptedException {
        response = IpvCoreStubUtil.sendSessionRequest(DEV_SESSION_URI, "");
        responseBodyMap = objectMapper.readValue(response.body(), new TypeReference<>() {});
    }

    @Then("expect a status code of {int} in the response")
    public void expect_status_code_in_response(int statusCode) {
        assertEquals(statusCode, response.statusCode());
    }

    @And("the request body has no {word}")
    public void remove_key(String key) throws IOException {
        Map<String, String> map =
                objectMapper.readValue(sessionRequestBody, new TypeReference<>() {});
        map.remove(key);
        sessionRequestBody = objectMapper.writeValueAsString(map);
    }

    @And("user sends an address")
    public void userSendsAnAddress() throws IOException, URISyntaxException, InterruptedException {
        IpvCoreStubUtil.sendAddress(sessionId);
    }

    @When("user sends a request to authorization end point")
    public void user_sends_a_request_to_authorization_end_point()
            throws IOException, InterruptedException, URISyntaxException {
        response = IpvCoreStubUtil.sendAuthorizationRequest(DEV_AUTHORIZATION_URI, sessionId);
    }

    @And("a valid authorization code is returned in the response")
    public void aValidAuthorizationCodeIsReturnedInTheResponse() throws IOException {
        JsonNode jsonNode = objectMapper.readTree(response.body());
        assertNotNull(jsonNode.get("authorizationCode").get("value").textValue());
        assertNotNull(jsonNode.get("redirectionURI").textValue());
        assertNotNull(jsonNode.get("state").get("value").textValue());
    }
}
