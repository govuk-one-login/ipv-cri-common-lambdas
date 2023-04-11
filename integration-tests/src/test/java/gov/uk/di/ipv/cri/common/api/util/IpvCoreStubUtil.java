package gov.uk.di.ipv.cri.common.api.util;

import org.apache.http.client.utils.URIBuilder;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;
import java.util.Optional;

import static gov.uk.di.ipv.cri.common.api.stepDefinitions.APISteps.DEV_ACCESS_TOKEN_URI;

public class IpvCoreStubUtil {

    private static final String CRI_DEV =
            Optional.ofNullable(System.getenv("CRI_DEV")).orElse("address-cri-dev");
    private static final String API_GATEWAY_ID_PRIVATE = "API_GATEWAY_ID_PRIVATE";

    public static String getPrivateApiEndpoint() {
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
                                        .addParameter("cri", CRI_DEV)
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
                        .addParameter("cri", CRI_DEV)
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

    public static HttpResponse<String> sendAuthorizationRequest(
            String apiPath, String sessionId, String redirectUri, String clientId)
            throws URISyntaxException, IOException, InterruptedException {
        var url =
                new URIBuilder(getPrivateApiEndpoint())
                        .setPath(apiPath)
                        .addParameter("redirect_uri", redirectUri)
                        .addParameter("client_id", clientId)
                        .addParameter("response_type", "code")
                        .addParameter("scope", "openid")
                        .addParameter("state", "state-ipv")
                        .build();
        HttpRequest request = getHttpRequest(sessionId, url);

        return sendHttpRequest(request);
    }

    public static void sendCreateAuthCodeRequest(String sessionId)
            throws URISyntaxException, IOException, InterruptedException {
        var request =
                getHttpRequest(
                        sessionId,
                        new URIBuilder(getPrivateApiEndpoint())
                                .setPath("dev/pre-merge-create-auth-code")
                                .build());
        sendHttpRequest(request);
    }

    private static HttpRequest getHttpRequest(String sessionId, URI url) throws URISyntaxException {
        var request =
                HttpRequest.newBuilder(url)
                        .setHeader("Accept", "application/json")
                        .setHeader("session-id", sessionId)
                        .GET()
                        .build();
        return request;
    }

    public static HttpResponse<String> sendAccessTokenRequest(String authorizationCode)
            throws URISyntaxException, IOException, InterruptedException {

        String privateKeyJWT = getPrivateKeyJWT(authorizationCode.trim());
        System.out.println("DEV_ACCESS_TOKEN_URI is --------" + DEV_ACCESS_TOKEN_URI);
        var request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(getPrivateApiEndpoint())
                                        .setPath(DEV_ACCESS_TOKEN_URI)
                                        .build())
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(privateKeyJWT))
                        .build();

        return sendHttpRequest(request);
    }

    private static String getPrivateKeyJWT(String authorizationCode)
            throws URISyntaxException, IOException, InterruptedException {
        return getPrivateKeyJWTFormParamsForAuthCode(getIPVCoreStubURL(), authorizationCode.trim());
    }

    private static String getPrivateKeyJWTFormParamsForAuthCode(
            String baseUrl, String authorizationCode)
            throws URISyntaxException, IOException, InterruptedException {
        var url =
                new URIBuilder(baseUrl)
                        .setPath("backend/createTokenRequestPrivateKeyJWT")
                        .addParameter("cri", CRI_DEV)
                        .addParameter("authorization_code", authorizationCode)
                        .build();

        HttpRequest request = HttpRequest.newBuilder().uri(url).GET().build();
        return sendHttpRequest(request).body();
    }
}
