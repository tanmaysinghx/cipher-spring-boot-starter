package io.github.tanmaysinghx.cipher.spring.bidx;

import io.github.tanmaysinghx.cipher.core.digest.HmacSigner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Objects;

/**
 * Thread-safe implementation of {@link BlindIndexService} using HMAC-SHA256 with pepper key.
 */
public class DefaultBlindIndexService implements BlindIndexService {

    private final HmacSigner hmacSigner;
    private final byte[] pepperKey;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    public DefaultBlindIndexService(byte[] pepperKey) {
        this(new HmacSigner("HmacSHA256"), pepperKey);
    }

    public DefaultBlindIndexService(HmacSigner hmacSigner, byte[] pepperKey) {
        this.hmacSigner = Objects.requireNonNull(hmacSigner, "HmacSigner must not be null");
        this.pepperKey = Objects.requireNonNull(pepperKey, "Pepper key must not be null").clone();

        if (pepperKey.length < 16) {
            throw new IllegalArgumentException("Blind index pepper key must be at least 16 bytes (128 bits)");
        }
    }

    @Override
    public String compute(String plaintext) {
        return compute(plaintext, "");
    }

    @Override
    public String compute(String plaintext, String context) {
        if (plaintext == null) {
            return null;
        }

        String input = (context != null && !context.isBlank()) ? (context + ":" + plaintext) : plaintext;
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        byte[] signature = hmacSigner.sign(data, pepperKey);
        return "bidx:" + encoder.encodeToString(signature);
    }

    @Override
    public boolean verify(String plaintext, String blindIndex) {
        if (plaintext == null || blindIndex == null) {
            return false;
        }
        String computed = compute(plaintext);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                blindIndex.getBytes(StandardCharsets.UTF_8)
        );
    }
}
