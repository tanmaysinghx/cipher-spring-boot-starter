package io.github.tanmaysinghx.cipher.core.digest;

import io.github.tanmaysinghx.cipher.core.exception.CipherException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Objects;

/**
 * High-performance, constant-time HMAC signer and verifier (HMAC-SHA256 / HMAC-SHA512).
 */
public final class HmacSigner {

    private static final String DEFAULT_ALGORITHM = "HmacSHA256";
    private final String hmacAlgorithm;

    public HmacSigner() {
        this(DEFAULT_ALGORITHM);
    }

    public HmacSigner(String hmacAlgorithm) {
        this.hmacAlgorithm = Objects.requireNonNull(hmacAlgorithm, "HMAC algorithm must not be null");
    }

    public byte[] sign(byte[] data, byte[] secretKey) {
        Objects.requireNonNull(data, "Data to sign must not be null");
        Objects.requireNonNull(secretKey, "Secret key must not be null");

        try {
            Mac mac = Mac.getInstance(hmacAlgorithm);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, hmacAlgorithm);
            mac.init(secretKeySpec);
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CipherException("HMAC computation failed: " + e.getMessage(), e);
        }
    }

    /**
     * Constant-time comparison to prevent side-channel timing attacks.
     *
     * @param data              original payload data
     * @param secretKey         secret key
     * @param expectedSignature signature to verify against
     * @return true if signature is valid, false otherwise
     */
    public boolean verify(byte[] data, byte[] secretKey, byte[] expectedSignature) {
        if (data == null || secretKey == null || expectedSignature == null) {
            return false;
        }
        byte[] computed = sign(data, secretKey);
        return MessageDigest.isEqual(computed, expectedSignature);
    }
}
