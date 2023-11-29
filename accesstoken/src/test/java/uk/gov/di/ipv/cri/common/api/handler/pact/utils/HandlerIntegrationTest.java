package uk.gov.di.ipv.cri.common.api.handler.pact.utils;

import java.lang.reflect.Field;
import java.net.HttpCookie;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public abstract class HandlerIntegrationTest<Q, S> {

    protected Map<String, String> constructHeaders(Optional<HttpCookie> cookie) {
        final Map<String, String> headers = new HashMap<>();
        cookie.ifPresent(c -> headers.put("Cookie", c.toString()));
        return headers;
    }

    protected Map<String, String> constructFrontendHeaders(String sessionId) {
        return constructFrontendHeaders(sessionId, Optional.empty(), Optional.empty());
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, String clientSessionId) {
        return constructFrontendHeaders(sessionId, Optional.of(clientSessionId), Optional.empty());
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId, String clientSessionId, String persistentSessionId) {
        return constructFrontendHeaders(
                sessionId, Optional.ofNullable(clientSessionId), Optional.of(persistentSessionId));
    }

    protected Map<String, String> constructFrontendHeaders(
            String sessionId,
            Optional<String> clientSessionId,
            Optional<String> persistentSessionId) {
        var headers = new HashMap<String, String>();
        headers.put("Session-Id", sessionId);
        clientSessionId.ifPresent(id -> headers.put("Client-Session-Id", id));
        persistentSessionId.ifPresent(id -> headers.put("di-persistent-session-id", id));
        return headers;
    }

    protected HttpCookie buildSessionCookie(String sessionID, String clientSessionID) {
        return new HttpCookie("gs", sessionID + "." + clientSessionID);
    }

    public static void setEnv(String key, String value) {
        try {
            Map<String, String> env = System.getenv();
            Class<?> cl = env.getClass();
            Field field = cl.getDeclaredField("m");
            field.setAccessible(true);
            Map<String, String> writableEnv = (Map<String, String>) field.get(env);
            writableEnv.put(key, value);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to set environment variable", e);
        }
    }
}
