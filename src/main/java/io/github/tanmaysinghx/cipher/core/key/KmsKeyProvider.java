package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;

/**
 * Service Provider Interface (SPI) for fetching cryptographic keys dynamically from external Key Management Services
 * (e.g. AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault).
 */
public interface KmsKeyProvider extends KeyProvider {

    /**
     * Provider name identifier (e.g. "aws-kms", "gcp-kms", "vault").
     *
     * @return provider name
     */
    String getProviderName();

    /**
     * Checks if this KMS provider is available and reachable.
     *
     * @return true if connected and healthy, false otherwise
     */
    boolean isHealthy();
}
