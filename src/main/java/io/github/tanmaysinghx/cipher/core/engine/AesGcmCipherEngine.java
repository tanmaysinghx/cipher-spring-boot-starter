package io.github.tanmaysinghx.cipher.core.engine;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import io.github.tanmaysinghx.cipher.core.exception.DecryptionFailedException;
import io.github.tanmaysinghx.cipher.core.exception.InvalidKeyException;
import io.github.tanmaysinghx.cipher.core.format.CipherPayload;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * High-performance, authenticated {@link CipherEngine} for AES in Galois/Counter Mode (GCM).
 * <p>
 * Complies with NIST SP 800-38D:
 * <ul>
 *     <li>96-bit (12 bytes) CSPRNG unique Nonce/IV per encryption</li>
 *     <li>128-bit (16 bytes) Authentication Tag</li>
 * </ul>
 */
public class AesGcmCipherEngine implements CipherEngine {

    private static final int TAG_LENGTH_BITS = 128;
    private final CipherAlgorithm algorithm;
    private final SecureRandom secureRandom;

    public AesGcmCipherEngine(CipherAlgorithm algorithm) {
        this(algorithm, new SecureRandom());
    }

    public AesGcmCipherEngine(CipherAlgorithm algorithm, SecureRandom secureRandom) {
        this.algorithm = Objects.requireNonNull(algorithm, "Algorithm must not be null");
        this.secureRandom = Objects.requireNonNull(secureRandom, "SecureRandom must not be null");

        if (algorithm != CipherAlgorithm.AES_256_GCM && algorithm != CipherAlgorithm.AES_128_GCM) {
            throw new IllegalArgumentException("AesGcmCipherEngine only supports AES_256_GCM or AES_128_GCM, given: " + algorithm);
        }
    }

    @Override
    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public CipherPayload encrypt(byte[] plaintext, SecretKeyHolder key, byte[] additionalAuthenticatedData) throws CipherException {
        validateKey(key);
        Objects.requireNonNull(plaintext, "Plaintext must not be null");

        byte[] iv = new byte[algorithm.getIvSizeBytes()];
        secureRandom.nextBytes(iv);

        try {
            Cipher cipher = Cipher.getInstance(algorithm.getTransformation());
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key.toSecretKey(), parameterSpec);

            if (additionalAuthenticatedData != null && additionalAuthenticatedData.length > 0) {
                cipher.updateAAD(additionalAuthenticatedData);
            }

            byte[] ciphertext = cipher.doFinal(plaintext);
            return new CipherPayload(key.getVersion(), iv, ciphertext, additionalAuthenticatedData);
        } catch (GeneralSecurityException e) {
            throw new CipherException("AES-GCM encryption failed: " + e.getMessage(), e);
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
            Cipher cipher = Cipher.getInstance(algorithm.getTransformation());
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, payload.iv());
            cipher.init(Cipher.DECRYPT_MODE, key.toSecretKey(), parameterSpec);

            byte[] aad = payload.additionalAuthenticatedData();
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }

            return cipher.doFinal(payload.ciphertext());
        } catch (AEADBadTagException e) {
            throw new DecryptionFailedException("AES-GCM decryption failed: authentication tag mismatch or corrupted ciphertext.", e);
        } catch (GeneralSecurityException e) {
            throw new DecryptionFailedException("AES-GCM decryption failed: " + e.getMessage(), e);
        }
    }

    private void validateKey(SecretKeyHolder key) {
        Objects.requireNonNull(key, "SecretKeyHolder must not be null");
        if (key.getAlgorithm() != algorithm) {
            throw new InvalidKeyException(String.format(
                    "Key algorithm mismatch: engine expects %s but key is configured for %s",
                    algorithm, key.getAlgorithm()
            ));
        }
    }
}
