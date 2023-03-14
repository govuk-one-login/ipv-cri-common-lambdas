package uk.gov.di.ipv.cri.common.api.serializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.DefaultDeserializationContext;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.TreeTraversingParser;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PIIRedactingDeserializerTest {
    private List<String> sensitiveFields = List.of("id", "name", "email");
    private ObjectMapper objectMapper;

    @Test
    public void shouldReturnNullWithNullRootNodeWhileAttemptingDeserialization() throws Exception {
        String json = "null";
        PIIRedactingDeserializer<Person> piiRedactingDeserializer =
                setUpRedactionModule(
                        Person.class,
                        () ->
                                new PIIRedactingDeserializer<>(
                                        Collections.emptyList(), Person.class));

        Object result =
                piiRedactingDeserializer.deserialize(
                        jsonParser(json), getDefaultDeserializationContext());

        assertThat(result, nullValue());
    }

    @Test
    public void shouldDeserializeWithoutRedactionWhenSensitiveFieldsAreNotSpecified()
            throws IOException {
        String json =
                "{\"name\":\"John\",\"email\":\"john.doe@example.com\",\"phone\":\"123456789\",\"city\":\"New York\"}";
        PIIRedactingDeserializer<Person> piiRedactingDeserializer =
                setUpRedactionModule(
                        Person.class,
                        () ->
                                new PIIRedactingDeserializer<>(
                                        Collections.emptyList(), Person.class));

        Person person =
                piiRedactingDeserializer.deserialize(
                        jsonParser(json), getDefaultDeserializationContext());

        assertThat(person.getName(), equalTo("John"));
        assertThat(person.getEmail(), equalTo("john.doe@example.com"));
        assertThat(person.getPhone(), equalTo("123456789"));
        assertThat(person.getCity(), equalTo("New York"));
    }

    @Test
    public void shouldDeserializeWithoutRedactionWhenSensitiveFieldsAreSpecified()
            throws IOException {
        String json =
                "{\"name\":\"John\",\"email\":\"john.doe@example.com\",\"phone\":\"123456789\",\"city\":\"New York\"}";
        List<String> sensitiveFields = List.of("email", "phone");
        PIIRedactingDeserializer<Person> piiRedactingDeserializer =
                setUpRedactionModule(
                        Person.class,
                        () -> new PIIRedactingDeserializer<>(sensitiveFields, Person.class));

        Person person =
                piiRedactingDeserializer.deserialize(
                        jsonParser(json), getDefaultDeserializationContext());

        assertThat(person.getName(), equalTo("John"));
        assertThat(person.getEmail(), equalTo("john.doe@example.com"));
        assertThat(person.getPhone(), equalTo("123456789"));
        assertThat(person.getCity(), equalTo("New York"));
    }

    @Test
    public void shouldThrowExceptionDuringDeserializationAndRedactAllFields() {
        String inValidJson =
                "{\"name\":\"John\",\"email\":\"john.doe@example.com\",\"age\":40,\"city\":\"New York\"}";
        PIIRedactingDeserializer<Person> piiRedactingDeserializer =
                setUpRedactionModule(
                        Person.class,
                        () ->
                                new PIIRedactingDeserializer<>(
                                        Collections.emptyList(), Person.class));

        JsonProcessingException exception =
                assertThrows(
                        JsonProcessingException.class,
                        () ->
                                piiRedactingDeserializer.deserialize(
                                        jsonParser(inValidJson),
                                        getDefaultDeserializationContext()));

        assertThat(
                exception.getMessage(),
                equalTo(
                        "Error while deserializing object. Some PII fields were redacted. {\"name\":\"******\",\"email\":\"******\",\"age\":\"******\",\"city\":\"******\"}"));
    }

    @Test
    public void shouldThrowExceptionDuringDeserializationAndRedactOnlySpecifiedFields() {
        String inValidJson =
                "{\"name\":\"John\",\"email\":\"john.doe@example.com\",\"age\":40,\"phone\":\"123456789\",\"city\":\"New York\"}";
        PIIRedactingDeserializer<Person> piiRedactingDeserializer =
                setUpRedactionModule(
                        Person.class,
                        () -> new PIIRedactingDeserializer<>(sensitiveFields, Person.class));

        JsonProcessingException exception =
                assertThrows(
                        JsonProcessingException.class,
                        () ->
                                piiRedactingDeserializer.deserialize(
                                        jsonParser(inValidJson),
                                        getDefaultDeserializationContext()));

        assertThat(
                exception.getMessage(),
                equalTo(
                        "Error while deserializing object. Some PII fields were redacted. {\"name\":\"******\",\"email\":\"******\",\"age\":40,\"phone\":\"123456789\",\"city\":\"New York\"}"));
    }

    private JsonParser jsonParser(String json) throws IOException {
        return objectMapper.getFactory().createParser(json);
    }

    private DefaultDeserializationContext getDefaultDeserializationContext() {
        JsonNode nullNode = objectMapper.getNodeFactory().nullNode();
        JsonParser nullParser = new TreeTraversingParser(nullNode);
        DeserializationConfig config = objectMapper.getDeserializationConfig();

        DefaultDeserializationContext context =
                new DefaultDeserializationContext.Impl(
                        objectMapper.getDeserializationContext().getFactory());
        context = context.createInstance(config, nullParser, objectMapper.getInjectableValues());
        return context;
    }

    private <T> PIIRedactingDeserializer setUpRedactionModule(
            Class<T> clazz, Supplier<PIIRedactingDeserializer<T>> deserializerSupplier) {
        PIIRedactingDeserializer deserializer = deserializerSupplier.get();
        SimpleModule redactionModule = new SimpleModule();
        redactionModule.addDeserializer(clazz, deserializer);
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule()).registerModule(redactionModule);
        return deserializer;
    }

    static class Person {
        private String name;
        private String email;
        private String phone;
        private String city;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPhone() {
            return phone;
        }

        public void setPhone(String phone) {
            this.phone = phone;
        }

        public String getCity() {
            return city;
        }

        public void setCity(String city) {
            this.city = city;
        }
    }
}
