package io.github.tanmaysinghx.cipher.core.engine;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;

/**
 * Core cryptographic engine interface responsible for encrypting and decrypting binary data.
 */
public interface CipherEngine {

    /**
     * Returns the algorithm supported by this engine.
     *
     * @return cipher algorithm
     */
    CipherAlgorithm getAlgorithm();

    /**
     * Encrypts plaintext bytes using the provided key and optional additional authenticated data (AAD).
     *
     * @param plaintext                 unencrypted plain bytes
     * @param key                       secret key holder
     * @param additionalAuthenticatedData optional AAD for AEAD authentication (or null)
     * @return the encrypted payload containing generated IV and ciphertext with authentication tag
     * @throws CipherException if encryption fails
     */
    CipherPayload encrypt(byte[] plaintext, SecretKeyHolder key, byte[] additionalAuthenticatedData) throws CipherException;

    /**
     * Decrypts ciphertext bytes from the provided payload using the provided key.
     *
     * @param payload the encrypted payload
     * @param key     secret key holder
     * @return the decrypted plain bytes
     * @throws DecryptionFailedException if authentication fails or ciphertext is corrupt
     * @throws CipherException           if decryption setup fails
     */
    byte[] decrypt(CipherPayload payload, SecretKeyHolder key) throws DecryptionFailedException, CipherException;
}
