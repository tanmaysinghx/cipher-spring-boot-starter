package io.github.tanmaysinghx.cipher.spring.actuator;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CipherHealthIndicatorTest {

    private DefaultCipherService cipherService;
    private MapKeyProvider keyProvider;
    private SecretKeyHolder keyHolder;
    private CipherHealthIndicator healthIndicator;

    @BeforeEach
    void setUp() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawKey);
        keyProvider = new MapKeyProvider("v1", Map.of("v1", keyHolder));

        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );
        cipherService = new DefaultCipherService(engines, keyProvider, new CompactPayloadFormatter());
        healthIndicator = new CipherHealthIndicator(cipherService, keyProvider);
    }

    @Test
    @DisplayName("Given healthy cipher keys and functioning engine, health status is UP with details")
    void shouldReportHealthUp() {
        Health health = healthIndicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("activeKeyVersion", "v1");
        assertThat(health.getDetails()).containsEntry("algorithm", "AES_256_GCM");
        assertThat(health.getDetails()).containsEntry("keySizeBits", 256);
    }

    @Test
    @DisplayName("Given destroyed active key, health status is DOWN")
    void shouldReportHealthDownWhenKeyIsDestroyed() {
        keyHolder.destroy();

        Health health = healthIndicator.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsKey("error");
    }
}
