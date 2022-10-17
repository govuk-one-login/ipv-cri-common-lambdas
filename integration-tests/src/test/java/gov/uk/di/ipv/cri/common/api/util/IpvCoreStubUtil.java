package gov.uk.di.ipv.cri.common.api.util;

import org.apache.http.client.utils.URIBuilder;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;
import java.util.Optional;

public class IpvCoreStubUtil {

    private static final String ADDRESS_CRI_DEV = "address-cri-dev";
    private static final String API_GATEWAY_ID_PRIVATE = "API_GATEWAY_ID_PRIVATE";
    private static final String ENVIRONMENT = "/dev"; // dev, build, staging, integration
    private static final String DEV_AUTHORIZATION_URI = ENVIRONMENT + "/authorization";

    private static String getPrivateApiEndpoint() {
        String apiEndpoint = System.getenv(API_GATEWAY_ID_PRIVATE);
        Optional.ofNullable(apiEndpoint)
                .orElseThrow(
                        () ->
                                new IllegalArgumentException(
                                        String.format(
                                                "Environment variable %s is not assigned",
                                                API_GATEWAY_ID_PRIVATE)));
        return "https://" + apiEndpoint + ".execute-api.eu-west-2.amazonaws.com";
    }

    public static String getClaimsForUser(int userDataRowNumber)
            throws URISyntaxException, IOException, InterruptedException {
        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(getIPVCoreStubURL())
                                        .setPath("backend/generateInitialClaimsSet")
                                        .addParameter("cri", ADDRESS_CRI_DEV)
                                        .addParameter(
                                                "rowNumber", String.valueOf(userDataRowNumber))
                                        .build())
                        .GET()
                        .build();
        return sendHttpRequest(request).body();
    }

    private static HttpResponse<String> sendHttpRequest(HttpRequest request)
            throws IOException, InterruptedException {

        String basicAuthUser =
                Objects.requireNonNull(
                        System.getenv("IPV_CORE_STUB_BASIC_AUTH_USER"),
                        "Environment variable IPV_CORE_STUB_BASIC_AUTH_USER is not set");
        String basicAuthPassword =
                Objects.requireNonNull(
                        System.getenv("IPV_CORE_STUB_BASIC_AUTH_PASSWORD"),
                        "Environment variable IPV_CORE_STUB_BASIC_AUTH_PASSWORD is not set");

        HttpClient client =
                HttpClient.newBuilder()
                        .authenticator(
                                new Authenticator() {
                                    @Override
                                    protected PasswordAuthentication getPasswordAuthentication() {
                                        return new PasswordAuthentication(
                                                basicAuthUser, basicAuthPassword.toCharArray());
                                    }
                                })
                        .build();

        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String getIPVCoreStubURL() {
        return Optional.ofNullable(System.getenv("IPV_CORE_STUB_URL"))
                .orElseThrow(
                        () ->
                                new IllegalArgumentException(
                                        "Environment variable IPV_CORE_STUB_URL is not set"));
    }

    public static String sendCreateSessionRequest(String jsonString)
            throws URISyntaxException, IOException, InterruptedException {

        var uri =
                new URIBuilder(getIPVCoreStubURL())
                        .setPath("backend/createSessionRequest")
                        .addParameter("cri", ADDRESS_CRI_DEV)
                        .build();

        HttpRequest request =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonString))
                        .build();

        return sendHttpRequest(request).body();
    }

    public static HttpResponse<String> sendSessionRequest(String apiPath, String sessionRequestBody)
            throws URISyntaxException, IOException, InterruptedException {
        var request =
                HttpRequest.newBuilder()
                        .uri(new URIBuilder(getPrivateApiEndpoint()).setPath(apiPath).build())
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(sessionRequestBody))
                        .build();
        return sendHttpRequest(request);
    }

    public static HttpResponse<String> createAuthorizationRequest(String sessionId)
            throws URISyntaxException, IOException, InterruptedException {
        var url =
                new URIBuilder(getPrivateApiEndpoint())
                        .setPath(DEV_AUTHORIZATION_URI)
                        .addParameter(
                                "redirect_uri",
                                "https://di-ipv-core-stub.london.cloudapps.digital/callback")
                        .addParameter("client_id", "ipv-core-stub")
                        .addParameter("response_type", "code")
                        .addParameter("scope", "openid")
                        .addParameter("state", "state-ipv")
                        .build();
        var request =
                HttpRequest.newBuilder()
                        .uri(url)
                        .setHeader("Accept", "application/json")
                        .setHeader("session-id", sessionId)
                        .GET()
                        .build();

        return sendHttpRequest(request);
    }

    public static HttpResponse<String> sendAuthorizationRequest(String apiPath, String sessionId)
            throws URISyntaxException, IOException, InterruptedException {
        var url =
                new URIBuilder(getPrivateApiEndpoint())
                        .setPath(apiPath)
                        .addParameter(
                                "redirect_uri",
                                "https://di-ipv-core-stub.london.cloudapps.digital/callback")
                        .addParameter("client_id", "ipv-core-stub")
                        .addParameter("response_type", "code")
                        .addParameter("scope", "openid")
                        .addParameter("state", "state-ipv")
                        .build();
        var request =
                HttpRequest.newBuilder()
                        .uri(url)
                        .setHeader("Accept", "application/json")
                        .setHeader("session-id", sessionId)
                        .GET()
                        .build();

        return sendHttpRequest(request);
    }

    public static void sendAddress(String sessionId)
            throws IOException, InterruptedException, URISyntaxException {

        String requestBody =
                "["
                        + "{"
                        + "    \"uprn\": \"123456789\","
                        + "    \"organisationName\": \"PRIME MINISTER & FIRST LORD OF THE TREASURY\","
                        + "    \"buildingNumber\": \"10\","
                        + "    \"thoroughfareName\": \"BERRYMEAD GARDENS\","
                        + "    \"postTown\": \"LONDON\","
                        + "    \"postcode\": \"W3 8AA\","
                        + "    \"countryCode\": \"GBR\","
                        + "    \"validFrom\": \"2021-01-01\""
                        + "  }"
                        + "]";

        var request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(getPrivateApiEndpoint())
                                        .setPath("/dev/address")
                                        .build())
                        .setHeader("session_id", sessionId)
                        .PUT(HttpRequest.BodyPublishers.ofString(requestBody))
                        .build();
        var response = sendHttpRequest(request);
        if (response.statusCode() != 204)
            throw new IllegalStateException(
                    "Address PUT endpoint returned status code: "
                            + response.statusCode()
                            + " with body: "
                            + response.body());
    }
}
