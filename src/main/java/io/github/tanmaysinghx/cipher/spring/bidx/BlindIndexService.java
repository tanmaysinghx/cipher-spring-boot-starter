package io.github.tanmaysinghx.cipher.spring.bidx;

/**
 * Service for computing deterministic blind indices to allow searching over encrypted database columns
 * (e.g., querying encrypted SSNs, emails, or phone numbers via {@code WHERE ssn_bidx = :bidx}).
 */
public interface BlindIndexService {

    /**
     * Computes a deterministic, salted blind index hash from plaintext.
     *
     * @param plaintext unencrypted value to index
     * @return deterministic blind index string (URL-safe base64 / hex)
     */
    String compute(String plaintext);

    /**
     * Computes a deterministic blind index with a specific tenant/column context.
     *
     * @param plaintext unencrypted value to index
     * @param context   tenant or column identifier preventing cross-column correlation
     * @return deterministic blind index string
     */
    String compute(String plaintext, String context);

    /**
     * Verifies if the plaintext matches a given blind index.
     *
     * @param plaintext  unencrypted candidate value
     * @param blindIndex existing blind index hash
     * @return true if matches, false otherwise
     */
    boolean verify(String plaintext, String blindIndex);
}
