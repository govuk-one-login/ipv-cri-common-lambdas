package uk.gov.di.ipv.cri.common.api.handler.pact;

import au.com.dius.pact.provider.junit.Provider;
import au.com.dius.pact.provider.junit.State;
import au.com.dius.pact.provider.junit.loader.PactBroker;
import au.com.dius.pact.provider.junit.loader.PactBrokerAuth;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import org.apache.http.HttpRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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
import uk.gov.di.ipv.cri.common.library.util.ListUtil;

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
@Provider("PassportCriProvider")
@PactBroker(
        host = "${PACT_BROKER_HOST}",
        scheme = "https",
        authentication =
                @PactBrokerAuth(
                        username = "${PACT_BROKER_USERNAME}",
                        password = "${PACT_BROKER_PASSWORD}"))
@ExtendWith(MockitoExtension.class)
class AccessTokenHandlerTest {

    private static final int PORT = 5050;

    @Mock private ConfigurationService configurationService;
    @Mock private DataStore<SessionItem> dataStore;

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context) throws IOException {

        Map<String, String> clientAuth = new HashMap<>();
        clientAuth.put("audience", "dummyPassportComponentId");
        clientAuth.put("authenticationAlg", "ES256");
        clientAuth.put("redirectUri", "http://localhost:5050");
        clientAuth.put(
                "publicSigningJwkBase64",
                "eyJrdHkiOiJFQyIsImQiOiIxeEhzTmJsQ1RHbzZRTjNLZHNEVmZXNl8wMEg1VFRaRFp6bzFQeEQ3Nm9jIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSmJEbkJ1dVJVRHJadGlqMmhxWlhyVkdMcWZnQXZzaWxlalVTTTBFRFFpOCIsInkiOiIxSEdWcjZmaVVvY3B6Szh5OHJxOE9sc2tSV29WRHItNGxQVXNrUG5ldzljIn0=");

        when(configurationService.getParametersForPath("/clients/ipv-core/jwtAuthentication"))
                .thenReturn(clientAuth);
        when(configurationService.getBearerAccessTokenTtl()).thenReturn(100L);

        Injector tokenHandlerInjector =
                new Injector(
                        new AccessTokenHandler(
                                new AccessTokenService(configurationService, new JWTVerifier()),
                                new SessionService(
                                        dataStore,
                                        configurationService,
                                        Clock.systemUTC(),
                                        new ListUtil()),
                                new EventProbe()),
                        "/token",
                        "/");
        MockHttpServer.startServer(new ArrayList<>(List.of(tokenHandlerInjector)), PORT);

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @State("dummyApiKey is a valid api key")
    void dummyAPIKeyIsValid() {}

    @State("dummyPassportComponentId is the passport CRI component ID")
    void componentIdIsSetToPassportCri() {}

    @State("Passport CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    void passportIsUsingExpectedSigningKey() {}

    @State("dummyAuthCode is a valid authorization code")
    void validAuthorisationCodeSupplied() {}

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context, HttpRequest request) {
        // Simulates session creation and CRI lambda completion by generating an auth code
        long todayPlusADay =
                LocalDate.now().plusDays(2).toEpochSecond(LocalTime.now(), ZoneOffset.UTC);
        when(configurationService.getSessionExpirationEpoch()).thenReturn(todayPlusADay);
        when(configurationService.getAuthorizationCodeExpirationEpoch()).thenReturn(todayPlusADay);

        SessionRequest sessionRequest = new SessionRequest();
        sessionRequest.setNotBeforeTime(new Date(todayPlusADay));
        sessionRequest.setClientId("ipv-core");
        sessionRequest.setAudience("dummyPassportComponentId");
        sessionRequest.setRedirectUri(URI.create("http://localhost:5050"));
        sessionRequest.setExpirationTime(new Date(todayPlusADay));
        sessionRequest.setIssuer("ipv-core");
        sessionRequest.setClientId("ipv-core");

        SessionService sessionService =
                new SessionService(
                        dataStore, configurationService, Clock.systemUTC(), new ListUtil());
        ArgumentCaptor<SessionItem> sessionItemArgumentCaptor =
                ArgumentCaptor.forClass(SessionItem.class);

        doNothing().when(dataStore).create(any(SessionItem.class));

        UUID sessionId = sessionService.saveSession(sessionRequest);

        verify(dataStore).create(sessionItemArgumentCaptor.capture());

        SessionItem savedSessionitem = sessionItemArgumentCaptor.getValue();

        when(dataStore.getItem(savedSessionitem.getSessionId().toString()))
                .thenReturn(savedSessionitem);

        SessionItem session = sessionService.getSession(sessionId.toString());
        session.setAccessToken("123456789");

        sessionService.createAuthorizationCode(session);
        session.setAuthorizationCode("dummyAuthCode");
        sessionService.updateSession(session);

        when(dataStore.getItemByIndex(SessionItem.AUTHORIZATION_CODE_INDEX, "dummyAuthCode"))
                .thenReturn(List.of(session));
        context.verifyInteraction();
    }
}
