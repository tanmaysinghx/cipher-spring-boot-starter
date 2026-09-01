package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.InvalidKeyException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Thread-safe, secure holder for cryptographic keys.
 * Defensively copies keys, implements zeroing on destruction, and strictly masks credentials in {@code toString()}.
 */
public final class SecretKeyHolder implements Destroyable, AutoCloseable {

    private final String version;
    private final CipherAlgorithm algorithm;
    private byte[] keyBytes;
    private volatile boolean destroyed;

    public SecretKeyHolder(String version, CipherAlgorithm algorithm, byte[] rawKeyBytes) {
        this.version = Objects.requireNonNull(version, "Key version must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "Cipher algorithm must not be null");
        Objects.requireNonNull(rawKeyBytes, "Raw key bytes must not be null");

        if (version.isBlank()) {
            throw new InvalidKeyException("Key version cannot be blank");
        }

        if (rawKeyBytes.length != algorithm.getKeySizeBytes()) {
            throw new InvalidKeyException(String.format(
                    "Invalid key length for algorithm %s: expected %d bytes (%d bits), but received %d bytes",
                    algorithm.name(),
                    algorithm.getKeySizeBytes(),
                    algorithm.getKeySizeBits(),
                    rawKeyBytes.length
            ));
        }

        // Defensive copy
        this.keyBytes = Arrays.copyOf(rawKeyBytes, rawKeyBytes.length);
        this.destroyed = false;
    }

    public String getVersion() {
        return version;
    }

    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public SecretKey toSecretKey() {
        checkNotDestroyed();
        return new SecretKeySpec(this.keyBytes, algorithm.getKeyAlgorithm());
    }

    public byte[] getEncodedCopy() {
        checkNotDestroyed();
        return Arrays.copyOf(this.keyBytes, this.keyBytes.length);
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("KeyHolder for version '" + version + "' has already been destroyed.");
        }
    }

    @Override
    public synchronized void destroy() {
        if (!destroyed && keyBytes != null) {
            Arrays.fill(keyBytes, (byte) 0);
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    @Override
    public void close() {
        destroy();
    }

    @Override
    public String toString() {
        return "SecretKeyHolder[version='" + version + "', algorithm=" + algorithm + ", key=***MASKED***]";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretKeyHolder that)) return false;
        if (destroyed || that.destroyed) return false;
        return Objects.equals(version, that.version) &&
                algorithm == that.algorithm &&
                Arrays.equals(keyBytes, that.keyBytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, algorithm);
    }
}
