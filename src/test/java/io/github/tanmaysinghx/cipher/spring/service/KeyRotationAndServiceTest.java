package io.github.tanmaysinghx.cipher.spring.service;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeyRotationAndServiceTest {

    private MapKeyProvider keyProvider;
    private DefaultCipherService cipherService;
    private SecretKeyHolder keyV1;
    private SecretKeyHolder keyV2;

    @BeforeEach
    void setUp() {
        byte[] rawV1 = new byte[32];
        byte[] rawV2 = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(rawV1);
        random.nextBytes(rawV2);

        keyV1 = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawV1);
        keyV2 = new SecretKeyHolder("v2", CipherAlgorithm.AES_256_GCM, rawV2);

        Map<String, SecretKeyHolder> keys = new HashMap<>();
        keys.put("v1", keyV1);
        keys.put("v2", keyV2);

        keyProvider = new MapKeyProvider("v1", keys);

        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );

        cipherService = new DefaultCipherService(engines, keyProvider, new CompactPayloadFormatter());
    }

    @Test
    @DisplayName("Given active key v1, when encrypting, payload is prefixed with v1")
    void shouldEncryptWithActiveKeyV1() {
        String plaintext = "Secret Credit Card 4111-2222-3333-4444";
        String encrypted = cipherService.encrypt(plaintext);

        assertThat(encrypted).startsWith("enc:v1:");
        assertThat(cipherService.decrypt(encrypted)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("Given key rotation to v2, old v1 ciphertext can still be decrypted, and reEncrypt upgrades to v2")
    void shouldSupportZeroDowntimeKeyRotation() {
        // Step 1: Encrypt data with active key v1
        String plaintext = "User PII Social Security Number 000-11-2222";
        String encryptedV1 = cipherService.encrypt(plaintext);
        assertThat(encryptedV1).startsWith("enc:v1:");

        // Step 2: Rotate active key to v2 in a new service instance or provider
        Map<String, SecretKeyHolder> keys = new HashMap<>();
        keys.put("v1", keyV1);
        keys.put("v2", keyV2);
        MapKeyProvider rotatedProvider = new MapKeyProvider("v2", keys);

        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );
        DefaultCipherService rotatedCipherService = new DefaultCipherService(engines, rotatedProvider, new CompactPayloadFormatter());

        // Step 3: Decrypt old v1 ciphertext using rotated service
        String decrypted = rotatedCipherService.decrypt(encryptedV1);
        assertThat(decrypted).isEqualTo(plaintext);

        // Step 4: New encryption uses v2
        String encryptedV2 = rotatedCipherService.encrypt(plaintext);
        assertThat(encryptedV2).startsWith("enc:v2:");

        // Step 5: Re-encrypt (data migration) upgrades v1 payload to v2
        String migratedCiphertext = rotatedCipherService.reEncrypt(encryptedV1);
        assertThat(migratedCiphertext).startsWith("enc:v2:");
        assertThat(rotatedCipherService.decrypt(migratedCiphertext)).isEqualTo(plaintext);
    }
}
