package io.github.tanmaysinghx.cipher.core.engine;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ChaCha20Poly1305CipherEngineTest {

    private ChaCha20Poly1305CipherEngine engine;
    private SecretKeyHolder keyHolder;

    @BeforeEach
    void setUp() {
        engine = new ChaCha20Poly1305CipherEngine();
        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.CHACHA20_POLY1305, keyBytes);
    }

    @Test
    @DisplayName("Given valid plaintext, when encrypting with ChaCha20-Poly1305, then decrypts accurately")
    void shouldEncryptAndDecryptChaCha20() {
        // Arrange
        byte[] plaintext = "ChaCha20 High-Speed Payload".getBytes(StandardCharsets.UTF_8);

        // Act
        CipherPayload payload = engine.encrypt(plaintext, keyHolder, null);
        byte[] decrypted = engine.decrypt(payload, keyHolder);

        // Assert
        assertThat(payload.iv()).hasSize(12);
        assertThat(new String(decrypted, StandardCharsets.UTF_8)).isEqualTo("ChaCha20 High-Speed Payload");
    }

    @Test
    @DisplayName("Given tampered ciphertext, when decrypting with ChaCha20-Poly1305, then throws DecryptionFailedException")
    void shouldFailDecryptionOnTamperedData() {
        // Arrange
        byte[] plaintext = "Tamper Test".getBytes(StandardCharsets.UTF_8);
        CipherPayload payload = engine.encrypt(plaintext, keyHolder, null);

        byte[] corruptedCiphertext = payload.ciphertext();
        corruptedCiphertext[corruptedCiphertext.length - 1] ^= 0x01; // Tamper Poly1305 MAC tag
        CipherPayload tamperedPayload = new CipherPayload(payload.keyVersion(), payload.iv(), corruptedCiphertext, null);

        // Act & Assert
        assertThatThrownBy(() -> engine.decrypt(tamperedPayload, keyHolder))
                .isInstanceOf(DecryptionFailedException.class);
    }
}
