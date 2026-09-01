package io.github.tanmaysinghx.cipher.spring.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import io.github.tanmaysinghx.cipher.spring.annotation.EncryptedField;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;

import java.io.IOException;
import java.util.Objects;

/**
 * Jackson serializer that encrypts marked fields transparently during JSON serialization.
 */
public class EncryptedJsonSerializer extends JsonSerializer<Object> implements ContextualSerializer {

    private final CipherService cipherService;
    private final String keyVersion;

    public EncryptedJsonSerializer(CipherService cipherService) {
        this(cipherService, null);
    }

    public EncryptedJsonSerializer(CipherService cipherService, String keyVersion) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
        this.keyVersion = keyVersion;
    }

    @Override
    public void serialize(Object value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (value == null) {
            gen.writeNull();
            return;
        }

        String plaintext = value.toString();
        String encrypted = (keyVersion != null && !keyVersion.isBlank())
                ? cipherService.encrypt(plaintext, keyVersion)
                : cipherService.encrypt(plaintext);

        gen.writeString(encrypted);
    }

    @Override
    public JsonSerializer<?> createContextual(SerializerProvider prov, BeanProperty property) throws JsonMappingException {
        if (property != null) {
            EncryptedField annotation = property.getAnnotation(EncryptedField.class);
            if (annotation == null) {
                annotation = property.getContextAnnotation(EncryptedField.class);
            }
            if (annotation != null && !annotation.keyVersion().isBlank()) {
                return new EncryptedJsonSerializer(cipherService, annotation.keyVersion());
            }
        }
        return this;
    }
}
