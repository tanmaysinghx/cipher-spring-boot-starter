package io.github.tanmaysinghx.cipher.spring.service;

import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.format.PayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.KeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.metrics.CipherMetrics;
import io.github.tanmaysinghx.cipher.spring.metrics.NoOpCipherMetrics;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

/**
 * Thread-safe, production implementation of {@link CipherService}.
 */
public class DefaultCipherService implements CipherService {

    private final Map<String, CipherEngine> engines;
    private final KeyProvider keyProvider;
    private final PayloadFormatter payloadFormatter;
    private final CipherMetrics metrics;

    public DefaultCipherService(
            Map<String, CipherEngine> engines,
            KeyProvider keyProvider,
            PayloadFormatter payloadFormatter
    ) {
        this(engines, keyProvider, payloadFormatter, new NoOpCipherMetrics());
    }

    public DefaultCipherService(
            Map<String, CipherEngine> engines,
            KeyProvider keyProvider,
            PayloadFormatter payloadFormatter,
            CipherMetrics metrics
    ) {
        this.engines = Map.copyOf(Objects.requireNonNull(engines, "Engines map must not be null"));
        this.keyProvider = Objects.requireNonNull(keyProvider, "KeyProvider must not be null");
        this.payloadFormatter = Objects.requireNonNull(payloadFormatter, "PayloadFormatter must not be null");
        this.metrics = metrics != null ? metrics : new NoOpCipherMetrics();

        if (this.engines.isEmpty()) {
            throw new IllegalArgumentException("At least one CipherEngine must be provided");
        }
    }

    @Override
    public String encrypt(String plaintext) {
        return encrypt(plaintext, null, null);
    }

    @Override
    public String encrypt(String plaintext, String keyVersion) {
        return encrypt(plaintext, keyVersion, null);
    }

    @Override
    public String encrypt(String plaintext, byte[] aad) {
        return encrypt(plaintext, null, aad);
    }

    @Override
    public String encrypt(String plaintext, String keyVersion, byte[] aad) {
        if (plaintext == null) {
            return null;
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encryptBytes(plaintextBytes, keyVersion, aad);
        return new String(encryptedBytes, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] encryptBytes(byte[] plaintext) {
        return encryptBytes(plaintext, null, null);
    }

    @Override
    public byte[] encryptBytes(byte[] plaintext, String keyVersion, byte[] aad) {
        if (plaintext == null) {
            return null;
        }

        SecretKeyHolder keyHolder = resolveKeyForEncryption(keyVersion);
        CipherEngine engine = getEngine(keyHolder.getAlgorithm().name());

        long startTime = System.nanoTime();
        boolean success = false;
        try {
            CipherPayload payload = engine.encrypt(plaintext, keyHolder, aad);
            String formatted = payloadFormatter.format(payload);
            byte[] result = formatted.getBytes(StandardCharsets.UTF_8);
            success = true;
            return result;
        } finally {
            metrics.recordEncryption(
                    System.nanoTime() - startTime,
                    success,
                    keyHolder.getAlgorithm().name(),
                    keyHolder.getVersion()
            );
        }
    }

    @Override
    public String decrypt(String ciphertext) {
        return decrypt(ciphertext, null);
    }

    @Override
    public String decrypt(String ciphertext, byte[] aad) {
        if (ciphertext == null) {
            return null;
        }
        byte[] ciphertextBytes = ciphertext.getBytes(StandardCharsets.UTF_8);
        byte[] decryptedBytes = decryptBytes(ciphertextBytes, aad);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] decryptBytes(byte[] ciphertext) {
        return decryptBytes(ciphertext, null);
    }

    @Override
    public byte[] decryptBytes(byte[] ciphertextBytes, byte[] aad) {
        if (ciphertextBytes == null) {
            return null;
        }

        String formatted = new String(ciphertextBytes, StandardCharsets.UTF_8);
        CipherPayload payload = payloadFormatter.parse(formatted);
        if (aad != null) {
            payload = new CipherPayload(payload.keyVersion(), payload.iv(), payload.ciphertext(), aad);
        }

        SecretKeyHolder keyHolder = keyProvider.getKey(payload.keyVersion());
        CipherEngine engine = getEngine(keyHolder.getAlgorithm().name());

        long startTime = System.nanoTime();
        boolean success = false;
        try {
            byte[] decrypted = engine.decrypt(payload, keyHolder);
            success = true;
            return decrypted;
        } finally {
            metrics.recordDecryption(
                    System.nanoTime() - startTime,
                    success,
                    keyHolder.getAlgorithm().name(),
                    keyHolder.getVersion()
            );
        }
    }

    @Override
    public boolean isEncrypted(String text) {
        return payloadFormatter.isEncrypted(text);
    }

    @Override
    public String reEncrypt(String ciphertext) {
        if (ciphertext == null || !isEncrypted(ciphertext)) {
            return ciphertext;
        }
        String decrypted = decrypt(ciphertext);
        return encrypt(decrypted);
    }

    private SecretKeyHolder resolveKeyForEncryption(String keyVersion) {
        if (keyVersion != null && !keyVersion.isBlank()) {
            return keyProvider.getKey(keyVersion);
        }
        return keyProvider.getActiveKey();
    }

    private CipherEngine getEngine(String algorithmName) {
        CipherEngine engine = engines.get(algorithmName);
        if (engine == null) {
            throw new CipherException("No CipherEngine registered for algorithm: " + algorithmName);
        }
        return engine;
    }
}
