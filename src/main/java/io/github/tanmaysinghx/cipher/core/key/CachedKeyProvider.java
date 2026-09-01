package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe caching wrapper for {@link KeyProvider} implementations (such as remote KMS/Vault)
 * with time-to-live (TTL) invalidation.
 */
public class CachedKeyProvider implements KeyProvider {

    private record CacheEntry(SecretKeyHolder keyHolder, Instant expiry) {}

    private final KeyProvider delegate;
    private final Duration ttl;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public CachedKeyProvider(KeyProvider delegate, Duration ttl) {
        this.delegate = Objects.requireNonNull(delegate, "Delegate KeyProvider must not be null");
        this.ttl = Objects.requireNonNull(ttl, "TTL must not be null");
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("Cache TTL must be strictly positive");
        }
    }

    @Override
    public SecretKeyHolder getKey(String version) throws KeyNotFoundException {
        Instant now = Instant.now();
        CacheEntry entry = cache.get(version);

        if (entry != null && now.isBefore(entry.expiry()) && !entry.keyHolder().isDestroyed()) {
            return entry.keyHolder();
        }

        SecretKeyHolder fetched = delegate.getKey(version);
        cache.put(version, new CacheEntry(fetched, now.plus(ttl)));
        return fetched;
    }

    private volatile CacheEntry activeKeyCache;

    @Override
    public SecretKeyHolder getActiveKey() throws KeyNotFoundException {
        Instant now = Instant.now();
        CacheEntry entry = activeKeyCache;
        if (entry != null && now.isBefore(entry.expiry()) && !entry.keyHolder().isDestroyed()) {
            return entry.keyHolder();
        }
        SecretKeyHolder activeKey = delegate.getActiveKey();
        this.activeKeyCache = new CacheEntry(activeKey, now.plus(ttl));
        cache.put(activeKey.getVersion(), this.activeKeyCache);
        return activeKey;
    }

    @Override
    public Set<String> getAvailableVersions() {
        return delegate.getAvailableVersions();
    }

    public void invalidateAll() {
        cache.clear();
    }
}
