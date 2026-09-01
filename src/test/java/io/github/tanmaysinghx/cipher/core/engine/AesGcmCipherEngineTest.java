package io.github.tanmaysinghx.cipher.core.engine;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.exception.InvalidKeyException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmCipherEngineTest {

    private AesGcmCipherEngine engine;
    private SecretKeyHolder validKey256;
    private SecretKeyHolder validKey128;

    @BeforeEach
    void setUp() {
        engine = new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM);

        byte[] keyBytes256 = new byte[32];
        new SecureRandom().nextBytes(keyBytes256);
        validKey256 = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, keyBytes256);

        byte[] keyBytes128 = new byte[16];
        new SecureRandom().nextBytes(keyBytes128);
        validKey128 = new SecretKeyHolder("v1-128", CipherAlgorithm.AES_128_GCM, keyBytes128);
    }

    @Test
    @DisplayName("Given valid plaintext, when encrypting and decrypting with AES-256-GCM, then plaintext is restored")
    void shouldEncryptAndDecryptSuccessfully() {
        // Arrange
        byte[] plaintext = "Enterprise Confidential Data 2026".getBytes(StandardCharsets.UTF_8);

        // Act
        CipherPayload payload = engine.encrypt(plaintext, validKey256, null);
        byte[] decrypted = engine.decrypt(payload, validKey256);

        // Assert
        assertThat(payload.iv()).hasSize(12);
        assertThat(payload.ciphertext()).isNotEmpty();
        assertThat(new String(decrypted, StandardCharsets.UTF_8)).isEqualTo("Enterprise Confidential Data 2026");
    }

    @Test
    @DisplayName("Given AAD during encryption, when decrypting with same AAD, then succeeds")
    void shouldEncryptAndDecryptWithAad() {
        // Arrange
        byte[] plaintext = "Sensitive Transaction Payload".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "tenant-id-42".getBytes(StandardCharsets.UTF_8);

        // Act
        CipherPayload payload = engine.encrypt(plaintext, validKey256, aad);
        byte[] decrypted = engine.decrypt(payload, validKey256);

        // Assert
        assertThat(new String(decrypted, StandardCharsets.UTF_8)).isEqualTo("Sensitive Transaction Payload");
    }

    @Test
    @DisplayName("Given tampered ciphertext, when decrypting, then throws DecryptionFailedException")
    void shouldFailDecryptionWhenCiphertextIsTampered() {
        // Arrange
        byte[] plaintext = "Tamper Test Payload".getBytes(StandardCharsets.UTF_8);
        CipherPayload payload = engine.encrypt(plaintext, validKey256, null);

        byte[] corruptedCiphertext = payload.ciphertext();
        corruptedCiphertext[0] ^= 0xFF; // Flip bits

        CipherPayload tamperedPayload = new CipherPayload(payload.keyVersion(), payload.iv(), corruptedCiphertext, null);

        // Act & Assert
        assertThatThrownBy(() -> engine.decrypt(tamperedPayload, validKey256))
                .isInstanceOf(DecryptionFailedException.class)
                .hasMessageContaining("AES-GCM decryption failed");
    }

    @Test
    @DisplayName("Given AAD mismatch, when decrypting, then throws DecryptionFailedException")
    void shouldFailDecryptionWhenAadMismatches() {
        // Arrange
        byte[] plaintext = "Sensitive Info".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "tenant-1".getBytes(StandardCharsets.UTF_8);
        CipherPayload payload = engine.encrypt(plaintext, validKey256, aad);

        byte[] wrongAad = "tenant-2".getBytes(StandardCharsets.UTF_8);
        CipherPayload mismatchAadPayload = new CipherPayload(payload.keyVersion(), payload.iv(), payload.ciphertext(), wrongAad);

        // Act & Assert
        assertThatThrownBy(() -> engine.decrypt(mismatchAadPayload, validKey256))
                .isInstanceOf(DecryptionFailedException.class);
    }

    @Test
    @DisplayName("Given multiple encryptions, ensures IVs/nonces are unique across iterations")
    void shouldGenerateUniqueIvsAcrossInvocations() {
        // Arrange
        byte[] plaintext = "Constant Plaintext".getBytes(StandardCharsets.UTF_8);
        int iterations = 1000;
        Set<String> observedIvs = new HashSet<>();

        // Act
        for (int i = 0; i < iterations; i++) {
            CipherPayload payload = engine.encrypt(plaintext, validKey256, null);
            String ivHex = java.util.HexFormat.of().formatHex(payload.iv());
            observedIvs.add(ivHex);
        }

        // Assert
        assertThat(observedIvs).hasSize(iterations);
    }

    @Test
    @DisplayName("Given mismatched algorithm key, when encrypting, then throws InvalidKeyException")
    void shouldRejectMismatchedKeyAlgorithm() {
        byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> engine.encrypt(plaintext, validKey128, null))
                .isInstanceOf(InvalidKeyException.class)
                .hasMessageContaining("Key algorithm mismatch");
    }
}
