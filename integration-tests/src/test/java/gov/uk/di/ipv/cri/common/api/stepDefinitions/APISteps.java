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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class APISteps {

    private static final String ENVIRONMENT = "/dev"; // dev, build, staging, integration
    private static final String DEV_SESSION_URI = ENVIRONMENT + "/session";
    private static final String DEV_AUTHORIZATION_URI = ENVIRONMENT + "/authorization";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String DEFAULT_REDIRECT_URI =
            "https://di-ipv-core-stub.london.cloudapps.digital/callback";
    private static final String DEFAULT_CLIENT_ID = "ipv-core-stub";
    private String sessionRequestBody;
    private String currentSessionId;
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
        currentSessionId = responseBodyMap.get("session_id");
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

    @When("user sends a valid request to authorization end point")
    public void user_sends_a_valid_request_to_authorization_end_point()
            throws IOException, InterruptedException, URISyntaxException {
        response =
                IpvCoreStubUtil.sendAuthorizationRequest(
                        DEV_AUTHORIZATION_URI,
                        currentSessionId,
                        DEFAULT_REDIRECT_URI,
                        DEFAULT_CLIENT_ID);
    }

    @And("a valid authorization code is returned in the response")
    public void aValidAuthorizationCodeIsReturnedInTheResponse() throws IOException {
        JsonNode jsonNode = objectMapper.readTree(response.body());
        assertEquals(
                UUID.fromString(jsonNode.get("authorizationCode").get("value").textValue())
                        .toString(),
                jsonNode.get("authorizationCode").get("value").textValue());
        assertEquals(DEFAULT_REDIRECT_URI, jsonNode.get("redirectionURI").textValue());
        assertEquals("state-ipv", jsonNode.get("state").get("value").textValue());
    }

    @When("user sends a request to authorization end point with invalid client id")
    public void user_sends_a_request_to_authorization_end_point_with_invalid_client_id()
            throws URISyntaxException, IOException, InterruptedException {
        response =
                IpvCoreStubUtil.sendAuthorizationRequest(
                        DEV_AUTHORIZATION_URI,
                        currentSessionId,
                        DEFAULT_REDIRECT_URI,
                        "INVALID-CLIENT-ID");
    }

    @When("user sends a request to authorization end point with invalid redirect uri")
    public void userSendsARequestToAuthorizationEndPointWithInvalidRedirectUri()
            throws URISyntaxException, IOException, InterruptedException {
        response =
                IpvCoreStubUtil.sendAuthorizationRequest(
                        DEV_AUTHORIZATION_URI,
                        currentSessionId,
                        "https://wrong-incorrect-url/callback",
                        DEFAULT_CLIENT_ID);
    }

    @And("a {string} error with code {int} is sent in the response body")
    public void aErrorWithCodeIsSentInTheResponseBody(String errorMessage, int errorCode)
            throws IOException {
        JsonNode jsonNode = objectMapper.readTree(response.body());
        assertEquals(errorCode, jsonNode.get("code").asInt());
        assertEquals("Session Validation Exception", errorMessage);
        assertEquals(errorCode + ": " + errorMessage, jsonNode.get("errorSummary").asText());
    }
}
