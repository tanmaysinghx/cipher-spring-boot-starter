package io.github.tanmaysinghx.cipher.benchmark;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

class ConcurrencyAndStressTest {

    @Test
    @DisplayName("Given concurrent threads, encrypt and decrypt operations are completely thread-safe and correct")
    void shouldHandleHighConcurrencySafely() throws Exception {
        // Arrange
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        SecretKeyHolder keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawKey);

        MapKeyProvider keyProvider = new MapKeyProvider("v1", Map.of("v1", keyHolder));
        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );

        DefaultCipherService cipherService = new DefaultCipherService(engines, keyProvider, new CompactPayloadFormatter());

        int threads = 16;
        int operationsPerThread = 2000;
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final int threadId = t;
                tasks.add(() -> {
                    for (int i = 0; i < operationsPerThread; i++) {
                        String original = "Thread-" + threadId + "-Payload-Index-" + i;
                        String encrypted = cipherService.encrypt(original);
                        String decrypted = cipherService.decrypt(encrypted);
                        if (!original.equals(decrypted)) {
                            return false;
                        }
                    }
                    return true;
                });
            }

            // Act
            List<Future<Boolean>> results = executor.invokeAll(tasks);

            // Assert
            for (Future<Boolean> result : results) {
                assertThat(result.get()).isTrue();
            }
        } finally {
            executor.shutdown();
        }
    }
}
