package io.github.tanmaysinghx.cipher.spring.jpa;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JpaAttributeConverterTest {

    private DefaultCipherService cipherService;
    private EncryptedStringAttributeConverter stringConverter;
    private EncryptedBytesAttributeConverter bytesConverter;

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
        CipherContextHolder.setCipherService(cipherService);

        stringConverter = new EncryptedStringAttributeConverter();
        bytesConverter = new EncryptedBytesAttributeConverter();
    }

    @AfterEach
    void tearDown() {
        CipherContextHolder.clear();
    }

    @Test
    @DisplayName("Given entity string attribute, converter converts to encrypted DB column and restores entity value")
    void shouldConvertStringAttributeToDatabaseColumnAndBack() {
        String originalValue = "Secret Database Field Value";

        String dbColumn = stringConverter.convertToDatabaseColumn(originalValue);
        assertThat(dbColumn).startsWith("enc:v1:");
        assertThat(dbColumn).isNotEqualTo(originalValue);

        String restoredValue = stringConverter.convertToEntityAttribute(dbColumn);
        assertThat(restoredValue).isEqualTo(originalValue);
    }

    @Test
    @DisplayName("Given entity byte[] attribute, converter converts to encrypted DB column bytes and restores entity value")
    void shouldConvertBytesAttributeToDatabaseColumnAndBack() {
        byte[] originalBytes = "Binary Secret Value".getBytes(StandardCharsets.UTF_8);

        byte[] dbColumnBytes = bytesConverter.convertToDatabaseColumn(originalBytes);
        assertThat(dbColumnBytes).isNotEmpty();

        byte[] restoredBytes = bytesConverter.convertToEntityAttribute(dbColumnBytes);
        assertThat(restoredBytes).isEqualTo(originalBytes);
    }

    @Test
    @DisplayName("Given null or non-encrypted inputs, converters gracefully handle without throwing exceptions")
    void shouldHandleNullAndPlaintextGracefully() {
        assertThat(stringConverter.convertToDatabaseColumn(null)).isNull();
        assertThat(stringConverter.convertToEntityAttribute(null)).isNull();
        assertThat(stringConverter.convertToEntityAttribute("plaintext-data")).isEqualTo("plaintext-data");

        assertThat(bytesConverter.convertToDatabaseColumn(null)).isNull();
        assertThat(bytesConverter.convertToEntityAttribute(null)).isNull();
    }
}
