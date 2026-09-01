package io.github.tanmaysinghx.cipher.core.engine;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.exception.InvalidKeyException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * High-performance, authenticated {@link CipherEngine} for ChaCha20-Poly1305 (RFC 8439).
 * <p>
 * Provides robust resistance against cache-timing attacks with 256-bit key and 96-bit nonce.
 */
public class ChaCha20Poly1305CipherEngine implements CipherEngine {

    private final SecureRandom secureRandom;

    public ChaCha20Poly1305CipherEngine() {
        this(new SecureRandom());
    }

    public ChaCha20Poly1305CipherEngine(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "SecureRandom must not be null");
    }

    @Override
    public CipherAlgorithm getAlgorithm() {
        return CipherAlgorithm.CHACHA20_POLY1305;
    }

    @Override
    public CipherPayload encrypt(byte[] plaintext, SecretKeyHolder key, byte[] additionalAuthenticatedData) throws CipherException {
        validateKey(key);
        Objects.requireNonNull(plaintext, "Plaintext must not be null");

        byte[] iv = new byte[getAlgorithm().getIvSizeBytes()];
        secureRandom.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(getAlgorithm().getTransformation());
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key.toSecretKey(), ivSpec);

            if (additionalAuthenticatedData != null && additionalAuthenticatedData.length > 0) {
                cipher.updateAAD(additionalAuthenticatedData);
            }

            byte[] ciphertext = cipher.doFinal(plaintext);
            return new CipherPayload(key.getVersion(), iv, ciphertext, additionalAuthenticatedData);
        } catch (GeneralSecurityException e) {
            throw new CipherException("ChaCha20-Poly1305 encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(CipherPayload payload, SecretKeyHolder key) throws DecryptionFailedException, CipherException {
        validateKey(key);
        Objects.requireNonNull(payload, "Payload must not be null");

        if (!Objects.equals(payload.keyVersion(), key.getVersion())) {
            throw new InvalidKeyException(String.format(
                    "Key version mismatch: payload version is '%s' but key version is '%s'",
                    payload.keyVersion(), key.getVersion()
            ));
        }

        try {
            Cipher cipher = Cipher.getInstance(getAlgorithm().getTransformation());
            IvParameterSpec ivSpec = new IvParameterSpec(payload.iv());
            cipher.init(Cipher.DECRYPT_MODE, key.toSecretKey(), ivSpec);

            byte[] aad = payload.additionalAuthenticatedData();
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(payload.ciphertext());
        } catch (AEADBadTagException e) {
            throw new DecryptionFailedException("ChaCha20-Poly1305 decryption failed: tag mismatch or corrupted ciphertext.", e);
        } catch (GeneralSecurityException e) {
            throw new DecryptionFailedException("ChaCha20-Poly1305 decryption failed: " + e.getMessage(), e);
        }
    }

    private void validateKey(SecretKeyHolder key) {
        Objects.requireNonNull(key, "SecretKeyHolder must not be null");
        if (key.getAlgorithm() != CipherAlgorithm.CHACHA20_POLY1305) {
            throw new InvalidKeyException(String.format(
                    "Key algorithm mismatch: engine expects %s but key is configured for %s",
                    CipherAlgorithm.CHACHA20_POLY1305, key.getAlgorithm()
            ));
        }
    }
}
