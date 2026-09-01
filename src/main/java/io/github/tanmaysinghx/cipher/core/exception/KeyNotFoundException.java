package io.github.tanmaysinghx.cipher.core.exception;

/**
 * Thrown when a requested cryptographic key identifier or version cannot be resolved.
 */
public class KeyNotFoundException extends CipherException {

    private static final long serialVersionUID = 1L;

    private final String keyVersion;

    public KeyNotFoundException(String keyVersion) {
        super("Cryptographic key not found for version: " + keyVersion);
        this.keyVersion = keyVersion;
    }

    public String getKeyVersion() {
        return keyVersion;
    }
}
