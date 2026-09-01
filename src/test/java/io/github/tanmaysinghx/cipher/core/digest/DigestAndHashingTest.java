package io.github.tanmaysinghx.cipher.core.digest;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class DigestAndHashingTest {

    @Test
    @DisplayName("Given payload and secret key, HMAC signing and constant-time verification succeed")
    void shouldSignAndVerifyHmac() {
        // Arrange
        HmacSigner signer = new HmacSigner();
        byte[] secretKey = new byte[32];
        new SecureRandom().nextBytes(secretKey);
        byte[] data = "AuditLogPayload".getBytes(StandardCharsets.UTF_8);

        // Act
        byte[] signature = signer.sign(data, secretKey);
        boolean isValid = signer.verify(data, secretKey, signature);

        byte[] tamperedData = "AuditLogPayload_TAMPERED".getBytes(StandardCharsets.UTF_8);
        boolean isTamperedValid = signer.verify(tamperedData, secretKey, signature);

        // Assert
        assertThat(isValid).isTrue();
        assertThat(isTamperedValid).isFalse();
    }

    @Test
    @DisplayName("Given raw string, Argon2Hasher hashes and correctly verifies with constant-time check")
    void shouldHashAndVerifyArgon2() {
        // Arrange
        Argon2Hasher hasher = new Argon2Hasher(2, 16384, 2, 32, new SecureRandom());
        String secretToken = "SuperSecureApiKey123!";

        // Act
        String hashed = hasher.hash(secretToken);
        boolean isValid = hasher.verify(secretToken, hashed);
        boolean isWrongValid = hasher.verify("WrongApiKey", hashed);

        // Assert
        assertThat(hashed).startsWith("$argon2id$");
        assertThat(isValid).isTrue();
        assertThat(isWrongValid).isFalse();
    }
}
