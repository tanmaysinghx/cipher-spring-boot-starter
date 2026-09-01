package io.github.tanmaysinghx.cipher.spring.metrics;

/**
 * Strategy interface for recording metrics on encryption and decryption operations.
 */
public interface CipherMetrics {

    /**
     * Records the duration and outcome of an encryption operation.
     *
     * @param durationNanos execution time in nanoseconds
     * @param success       true if encryption succeeded, false otherwise
     * @param algorithm     algorithm used
     * @param keyVersion    key version used
     */
    void recordEncryption(long durationNanos, boolean success, String algorithm, String keyVersion);

    /**
     * Records the duration and outcome of a decryption operation.
     *
     * @param durationNanos execution time in nanoseconds
     * @param success       true if decryption succeeded, false otherwise
     * @param algorithm     algorithm used
     * @param keyVersion    key version resolved
     */
    void recordDecryption(long durationNanos, boolean success, String algorithm, String keyVersion);
}
