package uk.gov.di.ipv.cri.common.api.serializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.BeanDeserializerFactory;
import com.fasterxml.jackson.databind.deser.ResolvableDeserializer;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.TypeFactory;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.function.Predicate;

public class PIIRedactingDeserializer<T> extends JsonDeserializer<T> {
    private final List<String> sensitiveFields;
    private final Class<T> clazz;
    private ObjectMapper objectMapper;

    public PIIRedactingDeserializer(List<String> sensitiveFields, Class<T> clazz) {
        this.sensitiveFields = sensitiveFields;
        this.clazz = clazz;
    }

    @Override
    public T deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException {
        JsonNode rootNode = null;
        try {
            this.objectMapper = (ObjectMapper) parser.getCodec();
            rootNode = this.objectMapper.readTree(parser);
            if (rootNode.isNull()) return null;

            DeserializationConfig config = ctxt.getConfig();
            JavaType type = TypeFactory.defaultInstance().constructType(clazz);
            JsonDeserializer<Object> defaultDeserializer =
                    BeanDeserializerFactory.instance.buildBeanDeserializer(
                            ctxt, type, config.introspect(type));

            if (defaultDeserializer instanceof ResolvableDeserializer) {
                ((ResolvableDeserializer) defaultDeserializer).resolve(ctxt);
            }

            JsonParser treeParser = objectMapper.treeAsTokens(rootNode);
            config.initialize(treeParser);

            if (treeParser.getCurrentToken() == null) {
                treeParser.nextToken();
            }

            return (T) defaultDeserializer.deserialize(treeParser, ctxt);
        } catch (JsonProcessingException e) {
            throw new SharedClaimParsingException(
                    "Error while deserializing object. Some PII fields were redacted. "
                            + processNode(rootNode, applySensitivity()));
        } catch (Exception e) {
            throw new SharedClaimParsingException(
                    "Unexpected error while deserializing object. Some PII fields may have been redacted. "
                            + processNode(rootNode, applySensitivity()));
        }
    }

    private Predicate<String> applySensitivity() {
        return sensitiveFields.isEmpty()
                ? defaultAllFieldsAsSensitive -> true
                : sensitiveFields::contains;
    }

    private <T> ObjectNode processNode(JsonNode rootNode, Predicate<T> sensitivityTest) {
        ObjectNode objectNode = this.objectMapper.createObjectNode();
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
        redactedNode.put(field, "******");
    }
}
