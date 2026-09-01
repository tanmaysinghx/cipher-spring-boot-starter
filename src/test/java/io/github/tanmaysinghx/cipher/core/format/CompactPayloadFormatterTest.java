package io.github.tanmaysinghx.cipher.core.format;

import io.github.tanmaysinghx.cipher.core.exception.InvalidCiphertextException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CompactPayloadFormatterTest {

    private CompactPayloadFormatter formatter;

    @BeforeEach
    void setUp() {
        formatter = new CompactPayloadFormatter("enc");
    }

    @Test
    @DisplayName("Given valid CipherPayload, when formatting and parsing, then payload is fully restored")
    void shouldFormatAndParseSuccessfully() {
        // Arrange
        byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        byte[] ciphertext = "EncryptedBytesWithAuthTag".getBytes(StandardCharsets.UTF_8);
        CipherPayload original = new CipherPayload("v1", iv, ciphertext, null);

        // Act
        String formatted = formatter.format(original);
        CipherPayload parsed = formatter.parse(formatted);

        // Assert
        assertThat(formatted).startsWith("enc:v1:");
        assertThat(parsed.keyVersion()).isEqualTo("v1");
        assertThat(parsed.iv()).isEqualTo(iv);
        assertThat(parsed.ciphertext()).isEqualTo(ciphertext);
    }

    @Test
    @DisplayName("Given valid formatted string, isEncrypted returns true; given plain text, returns false")
    void shouldCorrectlyDetectEncryptedStrings() {
        byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        byte[] ciphertext = new byte[]{10, 20, 30};
        String formatted = formatter.format(new CipherPayload("v2", iv, ciphertext, null));

        assertThat(formatter.isEncrypted(formatted)).isTrue();
        assertThat(formatter.isEncrypted("plain text value")).isFalse();
        assertThat(formatter.isEncrypted("enc:v1:only_two_parts")).isFalse();
        assertThat(formatter.isEncrypted(null)).isFalse();
    }

    @Test
    @DisplayName("Given malformed formatted strings, parsing throws InvalidCiphertextException")
    void shouldFailParsingOnMalformedInputs() {
        assertThatThrownBy(() -> formatter.parse("invalid:structure"))
                .isInstanceOf(InvalidCiphertextException.class);

        assertThatThrownBy(() -> formatter.parse("wrongprefix:v1:aXY=:Y2lwaGVy"))
                .isInstanceOf(InvalidCiphertextException.class);

        assertThatThrownBy(() -> formatter.parse("enc::aXY=:Y2lwaGVy"))
                .isInstanceOf(InvalidCiphertextException.class);

        assertThatThrownBy(() -> formatter.parse("enc:v1:!@#$:Y2lwaGVy"))
                .isInstanceOf(InvalidCiphertextException.class);
    }
}
