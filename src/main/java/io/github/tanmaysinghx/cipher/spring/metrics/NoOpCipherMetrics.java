package io.github.tanmaysinghx.cipher.spring.metrics;

/**
 * No-op implementation of {@link CipherMetrics} used when Micrometer is not available or metrics are disabled.
 */
public class NoOpCipherMetrics implements CipherMetrics {

    @Override
    public void recordEncryption(long durationNanos, boolean success, String algorithm, String keyVersion) {
        // No-op
    }

    @Override
    public void recordDecryption(long durationNanos, boolean success, String algorithm, String keyVersion) {
        // No-op
    }
}
