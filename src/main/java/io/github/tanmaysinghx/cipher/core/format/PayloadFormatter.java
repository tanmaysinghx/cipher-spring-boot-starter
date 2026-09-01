package io.github.tanmaysinghx.cipher.core.format;

import io.github.tanmaysinghx.cipher.core.exception.InvalidCiphertextException;

/**
 * Strategy interface for serializing and deserializing {@link CipherPayload} to and from string representations.
 */
public interface PayloadFormatter {

    /**
     * Formats the payload into a persistent string representation.
     *
     * @param payload the cipher payload
     * @return serialized string
     */
    String format(CipherPayload payload);

    /**
     * Parses the formatted string representation back into a {@link CipherPayload}.
     *
     * @param formatted the serialized string
     * @return parsed cipher payload
     * @throws InvalidCiphertextException if formatted string is malformed
     */
    CipherPayload parse(String formatted) throws InvalidCiphertextException;

    /**
     * Checks if the given text matches the expected encryption format structure.
     *
     * @param text input text to check
     * @return true if formatted as ciphertext, false otherwise
     */
    boolean isEncrypted(String text);
}
