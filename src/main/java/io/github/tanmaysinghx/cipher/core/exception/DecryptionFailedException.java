package io.github.tanmaysinghx.cipher.core.exception;

/**
 * Thrown when decryption fails due to corrupted data, tag mismatch, or invalid authentication.
 */
public class DecryptionFailedException extends CipherException {

    private static final long serialVersionUID = 1L;

    public DecryptionFailedException(String message) {
        super(message);
    }

    public DecryptionFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
