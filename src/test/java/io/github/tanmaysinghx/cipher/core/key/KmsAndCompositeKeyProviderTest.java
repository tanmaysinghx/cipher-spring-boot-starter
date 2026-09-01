package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KmsAndCompositeKeyProviderTest {

    @Test
    @DisplayName("Given CompositeKeyProvider, resolves keys across multiple delegates seamlessly")
    void shouldResolveKeysAcrossDelegates() {
        byte[] rawKey1 = new byte[32];
        byte[] rawKey2 = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(rawKey1);
        random.nextBytes(rawKey2);

        SecretKeyHolder key1 = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawKey1);
        SecretKeyHolder key2 = new SecretKeyHolder("v2", CipherAlgorithm.AES_256_GCM, rawKey2);

        KeyProvider provider1 = new MapKeyProvider("v1", Map.of("v1", key1));
        KeyProvider provider2 = new MapKeyProvider("v2", Map.of("v2", key2));

        CompositeKeyProvider composite = new CompositeKeyProvider(List.of(provider1, provider2));

        assertThat(composite.getKey("v1")).isEqualTo(key1);
        assertThat(composite.getKey("v2")).isEqualTo(key2);
        assertThat(composite.getActiveKey()).isEqualTo(key1);
        assertThat(composite.getAvailableVersions()).containsExactlyInAnyOrder("v1", "v2");

        assertThatThrownBy(() -> composite.getKey("v3"))
                .isInstanceOf(KeyNotFoundException.class);
    }

    @Test
    @DisplayName("Given CachedKeyProvider, caches calls to underlying provider within TTL duration")
    void shouldCacheKeyLookupsWithinTtl() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        SecretKeyHolder keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, rawKey);

        AtomicInteger callCount = new AtomicInteger(0);

        KeyProvider countingProvider = new KeyProvider() {
            @Override
            public SecretKeyHolder getKey(String version) {
                callCount.incrementAndGet();
                if ("v1".equals(version)) return keyHolder;
                throw new KeyNotFoundException(version);
            }

            @Override
            public SecretKeyHolder getActiveKey() {
                return getKey("v1");
            }

            @Override
            public Set<String> getAvailableVersions() {
                return Set.of("v1");
            }
        };

        CachedKeyProvider cached = new CachedKeyProvider(countingProvider, Duration.ofMinutes(5));

        // Call getKey multiple times
        cached.getKey("v1");
        cached.getKey("v1");
        assertThat(callCount.get()).isEqualTo(1);

        // Call getActiveKey multiple times
        cached.getActiveKey();
        cached.getActiveKey();
        assertThat(callCount.get()).isEqualTo(2);
    }
}
