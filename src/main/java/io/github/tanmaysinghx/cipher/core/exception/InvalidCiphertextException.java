package io.github.tanmaysinghx.cipher.core.exception;

/**
 * Thrown when ciphertext payload is malformed or improperly formatted.
 */
public class InvalidCiphertextException extends CipherException {

    private static final long serialVersionUID = 1L;

    public InvalidCiphertextException(String message) {
        super(message);
    }

    public InvalidCiphertextException(String message, Throwable cause) {
        super(message, cause);
    }
}
