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

    public static HttpResponse<String> sendHttpRequest(HttpRequest request)
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

    public static String getIPVCoreStubURL() {
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

    public static HttpResponse<String> sendSessionRequest(String sessionRequestBody)
            throws URISyntaxException, IOException, InterruptedException {
        var request =
                HttpRequest.newBuilder()
                        .uri(
                                new URIBuilder(getPrivateApiEndpoint())
                                        .setPath("/dev/session")
                                        .build())
                        .setHeader("Accept", "application/json")
                        .setHeader("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(sessionRequestBody))
                        .build();
        return sendHttpRequest(request);
    }
}
