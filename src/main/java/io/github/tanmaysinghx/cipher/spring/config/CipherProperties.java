package io.github.tanmaysinghx.cipher.spring.config;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration properties for the Cipher Spring Boot Starter.
 */
@ConfigurationProperties(prefix = "cipher")
@Validated
public class CipherProperties {

    /**
     * Whether encryption starter auto-configuration is enabled.
     */
    private boolean enabled = true;

    /**
     * Default cipher algorithm for new encryption operations.
     */
    @NotNull(message = "Cipher algorithm must not be null")
    private CipherAlgorithm algorithm = CipherAlgorithm.AES_256_GCM;

    /**
     * Active key version identifier used for all new encryption operations.
     */
    @NotBlank(message = "Active key version must be specified")
    private String activeKeyVersion = "v1";

    /**
     * Map of key version identifier to secret key material (Base64-encoded or Hex-encoded).
     */
    @NotEmpty(message = "At least one encryption key must be provided in cipher.keys")
    private Map<String, String> keys = new HashMap<>();

    /**
     * Serialized payload prefix (default: 'enc').
     */
    @NotBlank(message = "Payload prefix must not be blank")
    private String payloadPrefix = CompactPayloadFormatter.DEFAULT_PREFIX;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CipherAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String getActiveKeyVersion() {
        return activeKeyVersion;
    }

    public void setActiveKeyVersion(String activeKeyVersion) {
        this.activeKeyVersion = activeKeyVersion;
    }

    public Map<String, String> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, String> keys) {
        this.keys = keys;
    }

    public String getPayloadPrefix() {
        return payloadPrefix;
    }

    public void setPayloadPrefix(String payloadPrefix) {
        this.payloadPrefix = payloadPrefix;
    }

    private BlindIndex blindIndex = new BlindIndex();

    public BlindIndex getBlindIndex() {
        return blindIndex;
    }

    public void setBlindIndex(BlindIndex blindIndex) {
        this.blindIndex = blindIndex;
    }

    public static class BlindIndex {
        private boolean enabled = false;
        private String secretKey;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getSecretKey() {
            return secretKey;
        }

        public void setSecretKey(String secretKey) {
            this.secretKey = secretKey;
        }
    }
}
