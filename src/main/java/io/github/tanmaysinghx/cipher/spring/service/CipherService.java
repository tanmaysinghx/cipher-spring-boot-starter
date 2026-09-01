package io.github.tanmaysinghx.cipher.spring.service;

import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;

/**
 * Enterprise service interface for performing cryptographic operations, transparent encryption,
 * decryption, format checking, and zero-downtime key rotation.
 */
public interface CipherService {

    /**
     * Encrypts plaintext string using the currently configured active key.
     *
     * @param plaintext unencrypted text
     * @return formatted encrypted ciphertext string
     * @throws CipherException if encryption fails
     */
    String encrypt(String plaintext) throws CipherException;

    /**
     * Encrypts plaintext string using a specific key version.
     *
     * @param plaintext  unencrypted text
     * @param keyVersion target key version
     * @return formatted encrypted ciphertext string
     * @throws CipherException if encryption fails
     */
    String encrypt(String plaintext, String keyVersion) throws CipherException;

    /**
     * Encrypts plaintext string with additional authenticated data (AAD).
     *
     * @param plaintext unencrypted text
     * @param aad       additional authenticated data
     * @return formatted encrypted ciphertext string
     * @throws CipherException if encryption fails
     */
    String encrypt(String plaintext, byte[] aad) throws CipherException;

    /**
     * Encrypts plaintext string with specific key version and AAD.
     *
     * @param plaintext  unencrypted text
     * @param keyVersion target key version
     * @param aad        additional authenticated data
     * @return formatted encrypted ciphertext string
     * @throws CipherException if encryption fails
     */
    String encrypt(String plaintext, String keyVersion, byte[] aad) throws CipherException;

    /**
     * Encrypts raw plaintext bytes using the active key.
     *
     * @param plaintext unencrypted bytes
     * @return formatted encrypted ciphertext bytes
     * @throws CipherException if encryption fails
     */
    byte[] encryptBytes(byte[] plaintext) throws CipherException;

    /**
     * Encrypts raw plaintext bytes with specific key version and AAD.
     *
     * @param plaintext  unencrypted bytes
     * @param keyVersion target key version
     * @param aad        additional authenticated data
     * @return formatted encrypted ciphertext bytes
     * @throws CipherException if encryption fails
     */
    byte[] encryptBytes(byte[] plaintext, String keyVersion, byte[] aad) throws CipherException;

    /**
     * Decrypts formatted ciphertext string back into original plaintext.
     *
     * @param ciphertext formatted encrypted string
     * @return decrypted plaintext string
     * @throws DecryptionFailedException if authentication fails or ciphertext is corrupt
     * @throws CipherException           if decryption setup fails
     */
    String decrypt(String ciphertext) throws DecryptionFailedException, CipherException;

    /**
     * Decrypts formatted ciphertext string with expected AAD.
     *
     * @param ciphertext formatted encrypted string
     * @param aad        additional authenticated data
     * @return decrypted plaintext string
     * @throws DecryptionFailedException if authentication fails or ciphertext is corrupt
     * @throws CipherException           if decryption setup fails
     */
    String decrypt(String ciphertext, byte[] aad) throws DecryptionFailedException, CipherException;

    /**
     * Decrypts formatted ciphertext bytes back into original plaintext bytes.
     *
     * @param ciphertext formatted encrypted bytes
     * @return decrypted plaintext bytes
     * @throws DecryptionFailedException if authentication fails or ciphertext is corrupt
     * @throws CipherException           if decryption setup fails
     */
    byte[] decryptBytes(byte[] ciphertext) throws DecryptionFailedException, CipherException;

    /**
     * Decrypts formatted ciphertext bytes with expected AAD.
     *
     * @param ciphertext formatted encrypted bytes
     * @param aad        additional authenticated data
     * @return decrypted plaintext bytes
     * @throws DecryptionFailedException if authentication fails or ciphertext is corrupt
     * @throws CipherException           if decryption setup fails
     */
    byte[] decryptBytes(byte[] ciphertext, byte[] aad) throws DecryptionFailedException, CipherException;

    /**
     * Verifies if the supplied string is in an encrypted format.
     *
     * @param text candidate string
     * @return true if formatted as ciphertext, false otherwise
     */
    boolean isEncrypted(String text);

    /**
     * Re-encrypts ciphertext (created with an older key version) using the latest active key.
     *
     * @param ciphertext old formatted ciphertext string
     * @return new ciphertext string encrypted with the active key
     */
    String reEncrypt(String ciphertext);
}
