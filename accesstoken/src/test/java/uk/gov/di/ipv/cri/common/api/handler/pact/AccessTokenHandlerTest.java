package uk.gov.di.ipv.cri.common.api.handler.pact;

import au.com.dius.pact.provider.junit.Provider;
import au.com.dius.pact.provider.junit.State;
import au.com.dius.pact.provider.junit.loader.PactFolder;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;
import uk.gov.di.ipv.cri.common.api.handler.pact.utils.HandlerIntegrationTest;
import uk.gov.di.ipv.cri.common.library.domain.SessionRequest;
import uk.gov.di.ipv.cri.common.library.persistence.DataStore;
import uk.gov.di.ipv.cri.common.library.persistence.item.SessionItem;
import uk.gov.di.ipv.cri.common.library.service.ConfigurationService;
import uk.gov.di.ipv.cri.common.library.service.SessionService;
import uk.gov.di.ipv.cri.common.library.util.ListUtil;

import java.net.URI;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Provider("PassportCriProvider")
@PactFolder("pacts")
@ExtendWith(MockitoExtension.class)
class AccessTokenHandlerTest extends HandlerIntegrationTest {

    private static final int PORT = 5050;

    @Mock private ConfigurationService configurationService;
    @Mock private DataStore<SessionItem> dataStore;

    @BeforeAll
    static void setupServer() {}

    @BeforeEach
    void pactSetup(PactVerificationContext context)  {
        ClientAndServer mockServer = ClientAndServer.startClientAndServer(PORT);
        mockServer.when(
                HttpRequest.request("/token")
                        .withMethod("POST")
        ).respond(
                HttpResponse.response()
                        .withStatusCode(200)
                        .withHeader(new Header("Content-Type", "application/json; charset=UTF-8"))
                        .withBody("{\"access_token\":\"string\",\"expires_in\":100,\"token_type\":\"Bearer\"}")
        );
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
    void testMethod(PactVerificationContext context, org.apache.http.HttpRequest request) {
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

        context.verifyInteraction();
    }
}
