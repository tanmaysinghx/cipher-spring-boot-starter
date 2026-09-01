package io.github.tanmaysinghx.cipher.core.algorithm;

import java.util.Arrays;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Supported modern authenticated encryption algorithms (AEAD) and parameters.
 */
public enum CipherAlgorithm {

    AES_256_GCM(
            "AES/GCM/NoPadding",
            "AES",
            32, // 256 bits
            12, // 96 bits nonce / IV
            16  // 128 bits tag
    ),

    AES_128_GCM(
            "AES/GCM/NoPadding",
            "AES",
            16, // 128 bits
            12, // 96 bits nonce / IV
            16  // 128 bits tag
    ),

    CHACHA20_POLY1305(
            "ChaCha20-Poly1305",
            "ChaCha20",
            32, // 256 bits
            12, // 96 bits nonce / IV
            16  // 128 bits tag
    );

    private final String transformation;
    private final String keyAlgorithm;
    private final int keySizeBytes;
    private final int ivSizeBytes;
    private final int tagSizeBytes;

    private static final Map<String, CipherAlgorithm> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(Enum::name, Function.identity()));

    CipherAlgorithm(String transformation, String keyAlgorithm, int keySizeBytes, int ivSizeBytes, int tagSizeBytes) {
        this.transformation = transformation;
        this.keyAlgorithm = keyAlgorithm;
        this.keySizeBytes = keySizeBytes;
        this.ivSizeBytes = ivSizeBytes;
        this.tagSizeBytes = tagSizeBytes;
    }

    public String getTransformation() {
        return transformation;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public int getKeySizeBytes() {
        return keySizeBytes;
    }

    public int getKeySizeBits() {
        return keySizeBytes * 8;
    }

    public int getIvSizeBytes() {
        return ivSizeBytes;
    }

    public int getTagSizeBytes() {
        return tagSizeBytes;
    }

    public static CipherAlgorithm fromString(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Cipher algorithm name cannot be null or blank");
        }
        CipherAlgorithm algorithm = BY_NAME.get(name.trim().toUpperCase());
        if (algorithm == null) {
            throw new IllegalArgumentException("Unsupported cipher algorithm: " + name + 
                    ". Supported algorithms: " + Arrays.toString(CipherAlgorithm.values()));
        }
        return algorithm;
    }
}
