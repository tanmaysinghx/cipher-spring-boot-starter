package io.github.tanmaysinghx.cipher.core.exception;

/**
 * Root unchecked exception for all cryptographic operations within the cipher starter.
 */
public class CipherException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CipherException(String message) {
        super(message);
    }

    public CipherException(String message, Throwable cause) {
        super(message, cause);
    }
}
