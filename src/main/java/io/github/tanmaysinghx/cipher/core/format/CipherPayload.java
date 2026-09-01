package io.github.tanmaysinghx.cipher.core.format;

import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable value representation of an encrypted cryptographic payload.
 *
 * @param keyVersion                     version identifier of the key used to encrypt the payload
 * @param iv                             initialization vector / nonce (CSPRNG generated)
 * @param ciphertext                     encrypted ciphertext (including authentication tag for AEAD ciphers)
 * @param additionalAuthenticatedData    optional AAD bytes authenticated during encryption/decryption
 */
public record CipherPayload(
        String keyVersion,
        byte[] iv,
        byte[] ciphertext,
        byte[] additionalAuthenticatedData
) {
    public CipherPayload {
        Objects.requireNonNull(keyVersion, "Key version must not be null");
        Objects.requireNonNull(iv, "IV must not be null");
        Objects.requireNonNull(ciphertext, "Ciphertext must not be null");

        // Defensive copy
        iv = Arrays.copyOf(iv, iv.length);
        ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
        if (additionalAuthenticatedData != null) {
            additionalAuthenticatedData = Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
        }
    }

    @Override
    public byte[] iv() {
        return Arrays.copyOf(iv, iv.length);
    }

    @Override
    public byte[] ciphertext() {
        return Arrays.copyOf(ciphertext, ciphertext.length);
    }

    @Override
    public byte[] additionalAuthenticatedData() {
        return additionalAuthenticatedData == null ? null : Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
    }

    @Override
    public String toString() {
        return "CipherPayload[keyVersion='" + keyVersion + "', ivLength=" + iv.length + ", ciphertextLength=" + ciphertext.length + "]";
    }
}
