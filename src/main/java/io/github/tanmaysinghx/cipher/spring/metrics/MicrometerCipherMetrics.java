package io.github.tanmaysinghx.cipher.spring.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import java.time.Duration;
import java.util.Objects;

/**
 * Micrometer-backed implementation of {@link CipherMetrics}.
 */
public class MicrometerCipherMetrics implements CipherMetrics {

    private static final String METRIC_PREFIX = "cipher";
    private final MeterRegistry meterRegistry;

    public MicrometerCipherMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = Objects.requireNonNull(meterRegistry, "MeterRegistry must not be null");
    }

    @Override
    public void recordEncryption(long durationNanos, boolean success, String algorithm, String keyVersion) {
        Timer.builder(METRIC_PREFIX + ".encryption.timer")
                .description("Time taken for cryptographic encryption operations")
                .tag("algorithm", algorithm != null ? algorithm : "unknown")
                .tag("version", keyVersion != null ? keyVersion : "unknown")
                .tag("status", success ? "success" : "failure")
                .register(meterRegistry)
                .record(Duration.ofNanos(durationNanos));

        Counter.builder(METRIC_PREFIX + ".encryption.count")
                .description("Total number of cryptographic encryption operations")
                .tag("algorithm", algorithm != null ? algorithm : "unknown")
                .tag("version", keyVersion != null ? keyVersion : "unknown")
                .tag("status", success ? "success" : "failure")
                .register(meterRegistry)
                .increment();
    }

    @Override
    public void recordDecryption(long durationNanos, boolean success, String algorithm, String keyVersion) {
        Timer.builder(METRIC_PREFIX + ".decryption.timer")
                .description("Time taken for cryptographic decryption operations")
                .tag("algorithm", algorithm != null ? algorithm : "unknown")
                .tag("version", keyVersion != null ? keyVersion : "unknown")
                .tag("status", success ? "success" : "failure")
                .register(meterRegistry)
                .record(Duration.ofNanos(durationNanos));

        Counter.builder(METRIC_PREFIX + ".decryption.count")
                .description("Total number of cryptographic decryption operations")
                .tag("algorithm", algorithm != null ? algorithm : "unknown")
                .tag("version", keyVersion != null ? keyVersion : "unknown")
                .tag("status", success ? "success" : "failure")
                .register(meterRegistry)
                .increment();
    }
}
