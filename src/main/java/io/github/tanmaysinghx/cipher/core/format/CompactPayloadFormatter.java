package io.github.tanmaysinghx.cipher.core.format;

import io.github.tanmaysinghx.cipher.core.exception.InvalidCiphertextException;

import java.util.Base64;
import java.util.Objects;

/**
 * Compact, URL-safe and log-safe string formatter for {@link CipherPayload}.
 * <p>
 * Format: {@code "enc:<version>:<base64(iv)>:<base64(ciphertext)>"}
 */
public class CompactPayloadFormatter implements PayloadFormatter {

    public static final String DEFAULT_PREFIX = "enc";
    private static final String DELIMITER = ":";
    private static final int EXPECTED_PARTS = 4;

    private final String prefix;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public CompactPayloadFormatter() {
        this(DEFAULT_PREFIX);
    }

    public CompactPayloadFormatter(String prefix) {
        this.prefix = Objects.requireNonNull(prefix, "Prefix must not be null");
        if (prefix.isBlank() || prefix.contains(DELIMITER)) {
            throw new IllegalArgumentException("Prefix cannot be blank or contain delimiter '" + DELIMITER + "'");
        }
    }

    @Override
    public String format(CipherPayload payload) {
        Objects.requireNonNull(payload, "Payload must not be null");
        String encodedIv = encoder.encodeToString(payload.iv());
        String encodedCiphertext = encoder.encodeToString(payload.ciphertext());

        return prefix + DELIMITER + payload.keyVersion() + DELIMITER + encodedIv + DELIMITER + encodedCiphertext;
    }

    @Override
    public CipherPayload parse(String formatted) throws InvalidCiphertextException {
        if (formatted == null || formatted.isBlank()) {
            throw new InvalidCiphertextException("Ciphertext payload is null or blank");
        }

        String[] parts = formatted.split(DELIMITER, -1);
        if (parts.length != EXPECTED_PARTS) {
            throw new InvalidCiphertextException(String.format(
                    "Invalid ciphertext format: expected %d segments separated by '%s', but found %d",
                    EXPECTED_PARTS, DELIMITER, parts.length
            ));
        }

        if (!prefix.equals(parts[0])) {
            throw new InvalidCiphertextException("Invalid payload prefix: expected '" + prefix + "', found '" + parts[0] + "'");
        }

        String version = parts[1];
        if (version.isBlank()) {
            throw new InvalidCiphertextException("Ciphertext key version is missing or blank");
        }

        try {
            byte[] iv = decoder.decode(parts[2]);
            byte[] ciphertext = decoder.decode(parts[3]);

            if (iv.length == 0) {
                throw new InvalidCiphertextException("Initialization vector (IV) cannot be empty");
            }
            if (ciphertext.length == 0) {
                throw new InvalidCiphertextException("Ciphertext payload data cannot be empty");
            }

            return new CipherPayload(version, iv, ciphertext, null);
        } catch (IllegalArgumentException e) {
            throw new InvalidCiphertextException("Failed to decode Base64 payload components: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isEncrypted(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        if (!text.startsWith(prefix + DELIMITER)) {
            return false;
        }
        String[] parts = text.split(DELIMITER, -1);
        return parts.length == EXPECTED_PARTS && !parts[1].isBlank() && !parts[2].isBlank() && !parts[3].isBlank();
    }
}
