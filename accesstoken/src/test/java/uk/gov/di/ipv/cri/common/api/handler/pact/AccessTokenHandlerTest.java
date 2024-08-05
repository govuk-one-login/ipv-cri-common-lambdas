package uk.gov.di.ipv.cri.common.api.handler.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import au.com.dius.pact.provider.junitsupport.loader.SelectorBuilder;
import org.apache.hc.core5.http.HttpRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.cri.common.api.handler.AccessTokenHandler;
import uk.gov.di.ipv.cri.common.api.handler.pact.utils.Injector;
import uk.gov.di.ipv.cri.common.api.handler.pact.utils.MockHttpServer;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.AccessTokenService;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.JWTVerifier;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.EventProbe;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// For static tests against potential new contracts
// @PactFolder("pacts")
// For local tests the pact details will need set as environment variables
@Tag("Pact")
@Provider("${CRI_UNDER_TEST}")
@PactBroker(
        url = "https://${PACT_BROKER_HOST}",
        authentication =
                @PactBrokerAuth(
                        username = "${PACT_BROKER_USERNAME}",
                        password = "${PACT_BROKER_PASSWORD}"))
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AccessTokenHandlerTest {

    private static final int PORT = 5050;

    @Mock private ConfigurationService configurationService;
    @Mock private DataStore<SessionItem> dataStore;

    @au.com.dius.pact.provider.junitsupport.loader.PactBrokerConsumerVersionSelectors
    public static SelectorBuilder consumerVersionSelectors() {
        // Select Pacts for consumers deployed to production with branch 'FEAT-123'
        return new SelectorBuilder()
                .tag(System.getenv("CRI_UNDER_TEST"))
                .branch("main", "IpvCoreBack")
                .deployedOrReleased();
    }

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context) throws IOException {

        Injector tokenHandlerInjector =
                new Injector(
                        new AccessTokenHandler(
                                new AccessTokenService(configurationService, new JWTVerifier()),
                                new SessionService(
                                        dataStore, configurationService, Clock.systemUTC()),
                                new EventProbe()),
                        "/token",
                        "/");
        MockHttpServer.startServer(new ArrayList<>(List.of(tokenHandlerInjector)), PORT);

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @AfterEach
    public void tearDown() {
        MockHttpServer.stopServer();
    }

    @State("dummyApiKey is a valid api key")
    void dummyAPIKeyIsValid() {}

    @State("dummyInvalidAuthCode is an invalid authorization code")
    void invalidAuthCode() {
        // No Setup required fails validation prior to any session updates
    }

    @State("dummyPassportComponentId is the passport CRI component ID")
    void componentIdIsSetToPassportCri() {
        mockingAuthenticationConfig("dummyPassportComponentId");
    }

    @State("dummyFraudComponentId is the FRAUD CHECK CRI component ID")
    void componentIdIsSetToFraudCri() {
        mockingAuthenticationConfig("dummyFraudComponentId");
    }

    @State("dummyDrivingLicenceComponentId is the driving licence CRI component ID")
    void componentIdIsSetToDLCri() {
        mockingAuthenticationConfig("dummyDrivingLicenceComponentId");
    }

    @State("dummyAddressComponentId is the address CRI component ID")
    void componentIdIsSetToAddressCri() {
        mockingAuthenticationConfig("dummyAddressComponentId");
    }

    @State("Passport CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void passportIsUsingExpectedSigningKey() {}

    @State("FRAUD CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void fraudCheck2IsUsingExpectedSigningKey() {}

    @State("FRAUD CHECK CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void fraudCheckIsUsingExpectedSigningKey() {}

    @State("Driving licence CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void drivingLicenceIsUsingExpectedSigningKey() {}

    @State("Address CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void addressIsUsingExpectedSigningKey() {}

    @State("dummyAuthCode is a valid authorization code")
    void validAuthorisationCodeSupplied() {
        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);
        when(configurationService.getSessionExpirationEpoch()).thenReturn(todayPlusADay);
        when(configurationService.getAuthorizationCodeExpirationEpoch()).thenReturn(todayPlusADay);
        when(configurationService.getBearerAccessTokenTtl()).thenReturn(todayPlusADay);

        SessionRequest sessionRequest = new SessionRequest();
        sessionRequest.setNotBeforeTime(new Date(todayPlusADay));
        sessionRequest.setClientId("ipv-core");
        sessionRequest.setAudience("dummyPassportComponentId");
        sessionRequest.setRedirectUri(URI.create("http://localhost:5050"));
        sessionRequest.setExpirationTime(new Date(todayPlusADay));
        sessionRequest.setIssuer("ipv-core");
        sessionRequest.setClientId("ipv-core");

        SessionService sessionService =
                new SessionService(dataStore, configurationService, Clock.systemUTC());
        ArgumentCaptor<SessionItem> sessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        doNothing().when(dataStore).create(any(SessionItem.class));

        UUID sessionId = sessionService.saveSession(sessionRequest);

        verify(dataStore).create(sessionItemArgumentCaptor.capture());

        SessionItem savedSessionitem = sessionItemArgumentCaptor.getValue();

        when(dataStore.getItem(savedSessionitem.getSessionId().toString()))
                .thenReturn(savedSessionitem);

        updateSessionWithAuthCode(sessionService, sessionId, "dummyAuthCode");
    }

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context, HttpRequest request) {
        // Simulates session creation and CRI lambda completion by generating an auth code
        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);

        context.verifyInteraction();
    }

    private void updateSessionWithAuthCode(
            SessionService sessionService, UUID sessionId, String dummyAuthCode) {
        SessionItem session = sessionService.getSession(sessionId.toString());
        session.setAccessToken("123456789");

        sessionService.createAuthorizationCode(session);
        session.setAuthorizationCode(dummyAuthCode);
        sessionService.updateSession(session);

        when(dataStore.getItemByIndex(SessionItem.AUTHORIZATION_CODE_INDEX, dummyAuthCode))
                .thenReturn(List.of(session));
    }

    private void mockingAuthenticationConfig(String dummyComponentId) {
        Map<String, String> clientAuth = new HashMap<>();
        clientAuth.put("audience", dummyComponentId);
        clientAuth.put("authenticationAlg", "ES256");
        clientAuth.put("redirectUri", "http://localhost:5050");
        clientAuth.put(
                "publicSigningJwkBase64",
                "eyJrdHkiOiJFQyIsImQiOiJPWHQwUDA1WnNRY0s3ZVl1c2dJUHNxWmRhQkNJSmlXNGltd1V0bmFBdGhVIiwiY3J2IjoiUC0yNTYiLCJ4IjoiRTlaenVPb3FjVlU0cFZCOXJwbVR6ZXpqeU9QUmxPbVBHSkhLaThSU2xJTSIsInkiOiJLbFRNWnRoSFpVa1l6NUFsZVRROGpmZjBUSmlTM3EyT0I5TDVGdzR4QTA0In0="); // pragma: allowlist-secret not actually a secret

        when(configurationService.getParametersForPath("/clients/ipv-core/jwtAuthentication"))
                .thenReturn(clientAuth);
    }
}
