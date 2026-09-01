package io.github.tanmaysinghx.cipher.spring.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.annotation.EncryptedField;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CipherJacksonModuleTest {

    private ObjectMapper objectMapper;
    private DefaultCipherService cipherService;

    public record UserProfileDto(
            String id,
            String username,
            @EncryptedField String ssn,
            @EncryptedField String email
    ) {}

    @BeforeEach
    void setUp() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        SecretKeyHolder keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawKey);

        MapKeyProvider keyProvider = new MapKeyProvider("v1", Map.of("v1", keyHolder));
        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );

        cipherService = new DefaultCipherService(engines, keyProvider, new CompactPayloadFormatter());

        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new CipherJacksonModule(cipherService));
    }

    @Test
    @DisplayName("Given DTO with @EncryptedField, serialization encrypts sensitive fields and deserialization restores them")
    void shouldSerializeAndDeserializeEncryptedFieldsTransparently() throws Exception {
        // Arrange
        UserProfileDto dto = new UserProfileDto("user-101", "tanmaysingh", "123-45-6789", "tanmay@example.com");

        // Act: Serialize
        String json = objectMapper.writeValueAsString(dto);

        // Assert: JSON contains encrypted tokens for ssn and email, plaintext for id and username
        assertThat(json).contains("\"id\":\"user-101\"");
        assertThat(json).contains("\"username\":\"tanmaysingh\"");
        assertThat(json).doesNotContain("123-45-6789");
        assertThat(json).doesNotContain("tanmay@example.com");
        assertThat(json).contains("\"ssn\":\"enc:v1:");
        assertThat(json).contains("\"email\":\"enc:v1:");

        // Act: Deserialize
        UserProfileDto deserialized = objectMapper.readValue(json, UserProfileDto.class);

        // Assert: Deserialized object matches original
        assertThat(deserialized.id()).isEqualTo("user-101");
        assertThat(deserialized.username()).isEqualTo("tanmaysingh");
        assertThat(deserialized.ssn()).isEqualTo("123-45-6789");
        assertThat(deserialized.email()).isEqualTo("tanmay@example.com");
    }
}
