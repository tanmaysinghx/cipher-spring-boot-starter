package io.github.tanmaysinghx.cipher.core.digest;

import io.github.tanmaysinghx.cipher.core.exception.CipherException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Enterprise-grade, memory-hard hashing using Argon2id for password and blind index hashing.
 */
public final class Argon2Hasher {

    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_MEMORY_KB = 65536; // 64 MB
    private static final int DEFAULT_PARALLELISM = 4;
    private static final int DEFAULT_HASH_LENGTH_BYTES = 32;
    private static final int DEFAULT_SALT_LENGTH_BYTES = 16;

    private final int iterations;
    private final int memoryKb;
    private final int parallelism;
    private final int hashLengthBytes;
    private final SecureRandom secureRandom;

    public Argon2Hasher() {
        this(DEFAULT_ITERATIONS, DEFAULT_MEMORY_KB, DEFAULT_PARALLELISM, DEFAULT_HASH_LENGTH_BYTES, new SecureRandom());
    }

    public Argon2Hasher(int iterations, int memoryKb, int parallelism, int hashLengthBytes, SecureRandom secureRandom) {
        this.iterations = iterations;
        this.memoryKb = memoryKb;
        this.parallelism = parallelism;
        this.hashLengthBytes = hashLengthBytes;
        this.secureRandom = Objects.requireNonNull(secureRandom, "SecureRandom must not be null");
    }

    /**
     * Hashes the plaintext password / token with a freshly generated salt and returns a formatted string:
     * {@code "$argon2id$v=19$m=65536,t=3,p=4$<salt_b64>$<hash_b64>"}
     *
     * @param rawInput input string to hash
     * @return formatted Argon2 string
     */
    public String hash(String rawInput) {
        Objects.requireNonNull(rawInput, "Input string must not be null");
        byte[] salt = new byte[DEFAULT_SALT_LENGTH_BYTES];
        secureRandom.nextBytes(salt);

        byte[] inputBytes = rawInput.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] hash = generateHash(inputBytes, salt);

            String saltB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(salt);
            String hashB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            return String.format("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKb, iterations, parallelism, saltB64, hashB64);
        } finally {
            Arrays.fill(inputBytes, (byte) 0);
        }
    }

    /**
     * Verifies raw input against an encoded Argon2id string using constant-time comparison.
     *
     * @param rawInput      unhashed input
     * @param formattedHash formatted Argon2 hash
     * @return true if valid, false otherwise
     */
    public boolean verify(String rawInput, String formattedHash) {
        if (rawInput == null || formattedHash == null || !formattedHash.startsWith("$argon2id$")) {
            return false;
        }

        String[] parts = formattedHash.split("\\$");
        if (parts.length != 6) {
            return false;
        }

        try {
            byte[] salt = Base64.getUrlDecoder().decode(parts[4]);
            byte[] expectedHash = Base64.getUrlDecoder().decode(parts[5]);

            byte[] inputBytes = rawInput.getBytes(StandardCharsets.UTF_8);
            byte[] computedHash;
            try {
                computedHash = generateHash(inputBytes, salt);
            } finally {
                Arrays.fill(inputBytes, (byte) 0);
            }

            return MessageDigest.isEqual(computedHash, expectedHash);
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] generateHash(byte[] inputBytes, byte[] salt) {
        try {
            Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(iterations)
                    .withMemoryAsKB(memoryKb)
                    .withParallelism(parallelism)
                    .withSalt(salt);

            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(builder.build());

            byte[] result = new byte[hashLengthBytes];
            generator.generateBytes(inputBytes, result, 0, result.length);
            return result;
        } catch (Exception e) {
            throw new CipherException("Argon2 hashing computation failed: " + e.getMessage(), e);
        }
    }
}
