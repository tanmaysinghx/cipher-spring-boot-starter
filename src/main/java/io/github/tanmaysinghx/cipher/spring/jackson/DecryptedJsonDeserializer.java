package io.github.tanmaysinghx.cipher.spring.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;

import java.io.IOException;
import java.util.Objects;

/**
 * Jackson deserializer that decrypts incoming encrypted JSON strings transparently.
 */
public class DecryptedJsonDeserializer extends JsonDeserializer<String> {

    private final CipherService cipherService;

    public DecryptedJsonDeserializer(CipherService cipherService) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
    }

    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String value = p.getValueAsString();
        if (value == null || value.isBlank()) {
            return value;
        }

        if (cipherService.isEncrypted(value)) {
            return cipherService.decrypt(value);
        }

        return value;
    }
}
