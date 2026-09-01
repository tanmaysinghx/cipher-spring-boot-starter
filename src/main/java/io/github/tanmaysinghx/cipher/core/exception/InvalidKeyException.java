package io.github.tanmaysinghx.cipher.core.exception;

/**
 * Thrown when an invalid cryptographic key is supplied (e.g. incorrect length, invalid format).
 */
public class InvalidKeyException extends CipherException {

    private static final long serialVersionUID = 1L;

    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
