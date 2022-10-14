package gov.uk.di.ipv.cri.common.api.stepDefinitions;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import gov.uk.di.ipv.cri.common.api.util.IpvCoreStubUtil;
import io.cucumber.java.en.And;
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

public class APISteps {

    private String sessionRequestBody;
    private HttpResponse<String> response;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, String> bodyMap;
    private String authorizationCode;

    @Given("authorization JAR for test user {int}")
    public void setAuthorizationJARForTestUser(int rowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        String ipvCoreStubURL = IpvCoreStubUtil.getIPVCoreStubURL();
        String userIdentityJson = IpvCoreStubUtil.getClaimsForUser(ipvCoreStubURL, rowNumber);
        sessionRequestBody = IpvCoreStubUtil.createRequest(ipvCoreStubURL, userIdentityJson);
    }

    @When("user sends a request to session API")
    public void user_sends_a_request_to_session_api()
            throws URISyntaxException, IOException, InterruptedException {
        sendSessionRequest(HttpRequest.BodyPublishers.ofString(sessionRequestBody));
        bodyMap = objectMapper.readValue(response.body(), new TypeReference<>() {});
    }

    @Then("user gets a session id")
    public void user_gets_a_session_id() {
        assertEquals(201, response.statusCode());
        assertNotNull(bodyMap.get("session_id"));
    }

    @When("user sends an empty request to session end point")
    public void user_sends_an_empty_request_to_session_end_point()
            throws URISyntaxException, IOException, InterruptedException {
        sendSessionRequest(HttpRequest.BodyPublishers.noBody());
        String body = response.body();

        bodyMap = objectMapper.readValue(body, new TypeReference<>() {});
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

    @When("user sends a GET request to authorization end point")
    public void user_sends_a_get_request_to_authorization_end_point()
            throws IOException, InterruptedException, URISyntaxException {
        var url =
                new URIBuilder(IpvCoreStubUtil.getPrivateAPIEndpoint())
                        .setPath("/dev/authorization")
                        .addParameter(
                                "redirect_uri",
                                "https://di-ipv-core-stub.london.cloudapps.digital/callback")
                        .addParameter("client_id", "ipv-core-stub")
                        .addParameter("response_type", "code")
                        .addParameter("scope", "openid")
                        .addParameter("state", "state-ipv")
                        .build();

        var sessionId = bodyMap.get("session_id");
        System.out.println("✨✨✨✨ session id is " + sessionId);
        var request =
                HttpRequest.newBuilder()
                        .uri(url)
                        .setHeader("Accept", "application/json")
                        .setHeader("session-id", sessionId)
                        .GET()
                        .build();

        response = IpvCoreStubUtil.sendHttpRequest(request);
    }

    @And("a valid authorization code is returned in the response")
    public void aValidAuthorizationCodeIsReturnedInTheResponse() throws IOException {
        JsonNode jsonNode = objectMapper.readTree(response.body());
        authorizationCode = jsonNode.get("authorizationCode").get("value").textValue();
        assertNotNull(authorizationCode);
    }

    private void sendSessionRequest(HttpRequest.BodyPublisher sessionRequestBody)
            throws URISyntaxException, IOException, InterruptedException {
        var request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(IpvCoreStubUtil.getPrivateAPIEndpoint())
                                        .setPath("/dev/session")
                                        .build())
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(sessionRequestBody)
                        .build();
        response = IpvCoreStubUtil.sendHttpRequest(request);
    }
}
