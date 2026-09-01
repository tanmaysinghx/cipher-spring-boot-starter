package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;

import java.util.Set;

/**
 * Strategy interface for resolving cryptographic keys by version ID and obtaining the active encryption key.
 */
public interface KeyProvider {

    /**
     * Resolves the key associated with the specified version.
     *
     * @param version the key version identifier
     * @return the secret key holder
     * @throws KeyNotFoundException if no key is configured for the given version
     */
    SecretKeyHolder getKey(String version) throws KeyNotFoundException;

    /**
     * Obtains the primary active key used for new encryption operations.
     *
     * @return the active secret key holder
     * @throws KeyNotFoundException if the active key cannot be resolved
     */
    SecretKeyHolder getActiveKey() throws KeyNotFoundException;

    /**
     * Returns the set of all available key versions managed by this provider.
     *
     * @return an unmodifiable set of key version identifiers
     */
    Set<String> getAvailableVersions();
}
