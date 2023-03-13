package uk.gov.di.ipv.cri.common.api.serializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;

public class PiiRedactingDeserializer<T> extends JsonDeserializer<T> {
    private final List<String> sensitiveFields;
    private final ObjectMapper objectMapper;

    public PiiRedactingDeserializer(List<String> sensitiveFields) {
        this.sensitiveFields = sensitiveFields;
        objectMapper = new ObjectMapper();
    }

    @Override
    public T deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException {
        JsonNode rootNode = parser.getCodec().readTree(parser);
        if (rootNode.isNull()) {
            return null;
        }
        ObjectNode objectNode = processObjectNodes(rootNode, sensitiveFields::contains);
        try {
            return objectMapper.treeToValue(
                    objectNode, (Class<T>) ctxt.getContextualType().getRawClass());
        } catch (JsonProcessingException e) {
            throw new PiiJsonProcessingException(
                    "Error while deserializing object. Some PII fields were redacted. "
                            + processObjectNodes(objectNode, i -> true));
        } catch (Exception e) {
            throw new PiiJsonProcessingException("Unexpected error while deserializing object. Some PII fields may have been redacted. " + objectNode);
        }
    }

    private <T> ObjectNode processObjectNodes(JsonNode rootNode, Predicate<T> sensitivityTest) {
        ObjectNode objectNode = objectMapper.createObjectNode();
        for (Iterator<String> it = rootNode.fieldNames(); it.hasNext(); ) {
            String field = it.next();
            if (sensitivityTest.test((T) field)) {
                redactField(objectNode, field);
            } else {
                objectNode.set(field, rootNode.get(field));
            }
        }
        return objectNode;
    }

    private void redactField(ObjectNode redactedNode, String field) {
        JsonNode valueNode = redactedNode.get(field);
        if (valueNode == null || valueNode.isNull()) {
            redactedNode.putNull(field);
        } else if (valueNode.isValueNode()) {
            redactValue(redactedNode, field, valueNode);
        } else {
            redactedNode.set(field, objectMapper.createObjectNode());
        }
    }

    private void redactValue(ObjectNode redactedNode, String field, JsonNode valueNode) {
        if (valueNode.isNumber() || valueNode.isBoolean()) {
            redactedNode.putNull(field);
        } else {
            redactedNode.put(field, "******");
        }
    }
}
