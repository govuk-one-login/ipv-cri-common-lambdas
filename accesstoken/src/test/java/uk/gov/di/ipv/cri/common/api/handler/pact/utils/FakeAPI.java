package uk.gov.di.ipv.cri.common.api.handler.pact.utils;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.mock;

public class FakeAPI {

    public static void startServer(ArrayList<Injector> endpointList) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(5050), 0);
        endpointList.forEach(
                (injector) ->
                        server.createContext(injector.getEndpoint(), new WrapperHandler(injector)));
        server.setExecutor(null); // creates a default executor
        server.start();
    }
}

class WrapperHandler implements HttpHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;
    private final Map<Integer, String> pathParamsFromInjector;

    public WrapperHandler(Injector injector) {
        this.handler = injector.getHandler();
        this.pathParamsFromInjector = injector.getPathParams();
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        try {
            APIGatewayProxyRequestEvent request = translateRequest(exchange);

            Context context = mock(Context.class);

            APIGatewayProxyResponseEvent response = this.handler.handleRequest(request, context);

            LOGGER.info("RESPONSE FROM HANDLER");
            LOGGER.info(response.getBody());

            translateResponse(response, exchange);

        } catch (Exception e) {
            LOGGER.info("error was caught");
            LOGGER.info(e.getMessage(), e);
            String err = "some error happened";
            exchange.sendResponseHeaders(500, err.length());
            OutputStream os = exchange.getResponseBody();
            os.write(err.getBytes());
            os.flush();
            os.close();
        }
    }

    private Map<String, String> getHeaderMap(Headers h) {
        Map<String, String> tempMap = new HashMap<>();
        h.keySet().forEach(key -> tempMap.put(key, String.join(", ", h.get(key))));
        return tempMap;
    }

    private Map<String, String> getPathParameters(String requestURL) {
        HashMap<String, String> stringStringHashMap = new HashMap<>();
        String[] pathArr = requestURL.split("/");
        LOGGER.info("CHECKING IF ANY PATH PARAMS: " + Arrays.toString(pathArr));
        if (pathParamsFromInjector.isEmpty() || pathArr.length <= 1) return stringStringHashMap;
        LOGGER.info("FOUND PATH PARAMS");
        pathParamsFromInjector
                .keySet()
                .forEach(
                        key ->
                                stringStringHashMap.put(
                                        pathParamsFromInjector.get(key), pathArr[key]));
        return stringStringHashMap;
    }

    private Map<String, String> getQueryStringParams(String queryString) {
        HashMap<String, String> stringStringHashMap = new HashMap<>();
        String[] arr = queryString.split("[&=]");
        if (arr.length < 2 || arr.length % 2 != 0) {
            LOGGER.info("query params possibly malformed");
            LOGGER.info(Arrays.toString(arr));
        }
        for (int i = 0; i < arr.length - 1; i += 2) {
            LOGGER.info("adding query params: " + arr[i] + " " + arr[i + 1]);
            stringStringHashMap.put(arr[i], arr[i + 1]);
        }
        return stringStringHashMap;
    }

    private APIGatewayProxyRequestEvent translateRequest(HttpExchange request) throws IOException {

        String requestBody = IOUtils.toString(request.getRequestBody(), StandardCharsets.UTF_8);
        LOGGER.info("BODY FROM ORIGINAL REQUEST");
        LOGGER.info(requestBody);

        String requestPath = request.getRequestURI().getPath();

        LOGGER.info(requestPath);

        Headers requestHeaders = request.getRequestHeaders();

        String requestId = UUID.randomUUID().toString();

        APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                new APIGatewayProxyRequestEvent()
                        .withBody(requestBody)
                        .withHeaders(getHeaderMap(requestHeaders))
                        .withHttpMethod(request.getRequestMethod())
                        .withPathParameters(getPathParameters(requestPath))
                        .withRequestContext(
                                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                        .withRequestId(requestId));
        String requestQuery = request.getRequestURI().getQuery();
        LOGGER.info("query retrieved: " + requestQuery);

        if (requestQuery != null) {
            apiGatewayProxyRequestEvent.setQueryStringParameters(
                    getQueryStringParams(requestQuery));
        }

        LOGGER.info("BODY FROM AG FORMED REQUEST");
        LOGGER.info(apiGatewayProxyRequestEvent.getBody());

        return apiGatewayProxyRequestEvent;
    }

    private void translateResponse(APIGatewayProxyResponseEvent response, HttpExchange exchange)
            throws IOException {
        Integer statusCode = response.getStatusCode();
        Map<String, String> apiResponseHeaders =
                new HashMap<>() {
                    {
                        response.getHeaders();
                    }
                };
        apiResponseHeaders.put("Content-Type", "application/json");
        Headers serverResponseHeaders = exchange.getResponseHeaders();
        apiResponseHeaders.forEach(serverResponseHeaders::set);

        if (response.getBody().isEmpty()) {
            LOGGER.info("empty body");
            exchange.sendResponseHeaders(statusCode, 0);
            OutputStream os = exchange.getResponseBody();
            // os.write(response.toString().getBytes());
            os.flush();
            os.close();
        } else {
            LOGGER.info("getting response body");
            String body = response.getBody();
            exchange.sendResponseHeaders(statusCode, body.length());
            OutputStream os = exchange.getResponseBody();
            os.write(body.getBytes());
            os.flush();
            os.close();
        }
    }
}
