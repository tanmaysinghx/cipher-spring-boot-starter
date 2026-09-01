package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory thread-safe implementation of {@link KeyProvider}.
 */
public class MapKeyProvider implements KeyProvider {

    private final Map<String, SecretKeyHolder> keys = new ConcurrentHashMap<>();
    private final String activeVersion;

    public MapKeyProvider(String activeVersion, Map<String, SecretKeyHolder> initialKeys) {
        this.activeVersion = Objects.requireNonNull(activeVersion, "Active key version must not be null");
        Objects.requireNonNull(initialKeys, "Initial keys map must not be null");

        if (!initialKeys.containsKey(activeVersion)) {
            throw new IllegalArgumentException("Active key version '" + activeVersion + "' must be present in the keys map.");
        }

        this.keys.putAll(initialKeys);
    }

    @Override
    public SecretKeyHolder getKey(String version) {
        if (version == null || version.isBlank()) {
            throw new KeyNotFoundException(version);
        }
        SecretKeyHolder key = keys.get(version);
        if (key == null || key.isDestroyed()) {
            throw new KeyNotFoundException(version);
        }
        return key;
    }

    @Override
    public SecretKeyHolder getActiveKey() {
        return getKey(activeVersion);
    }

    @Override
    public Set<String> getAvailableVersions() {
        return Collections.unmodifiableSet(keys.keySet());
    }

    public void registerKey(SecretKeyHolder keyHolder) {
        Objects.requireNonNull(keyHolder, "Key holder cannot be null");
        keys.put(keyHolder.getVersion(), keyHolder);
    }
}
