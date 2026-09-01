package io.github.tanmaysinghx.cipher.core.key;

import io.github.tanmaysinghx.cipher.core.exception.KeyNotFoundException;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Composite {@link KeyProvider} delegating key resolution sequentially across multiple providers.
 */
public class CompositeKeyProvider implements KeyProvider {

    private final List<KeyProvider> delegates;

    public CompositeKeyProvider(List<KeyProvider> delegates) {
        Objects.requireNonNull(delegates, "Delegates list must not be null");
        if (delegates.isEmpty()) {
            throw new IllegalArgumentException("At least one KeyProvider delegate must be configured");
        }
        this.delegates = List.copyOf(delegates);
    }

    @Override
    public SecretKeyHolder getKey(String version) throws KeyNotFoundException {
        for (KeyProvider delegate : delegates) {
            try {
                SecretKeyHolder key = delegate.getKey(version);
                if (key != null && !key.isDestroyed()) {
                    return key;
                }
            } catch (KeyNotFoundException ignored) {
                // Continue to next delegate
            }
        }
        throw new KeyNotFoundException(version);
    }

    @Override
    public SecretKeyHolder getActiveKey() throws KeyNotFoundException {
        for (KeyProvider delegate : delegates) {
            try {
                SecretKeyHolder activeKey = delegate.getActiveKey();
                if (activeKey != null && !activeKey.isDestroyed()) {
                    return activeKey;
                }
            } catch (KeyNotFoundException ignored) {
                // Continue to next delegate
            }
        }
        throw new KeyNotFoundException("Active key could not be resolved from any configured KeyProvider delegate.");
    }

    @Override
    public Set<String> getAvailableVersions() {
        Set<String> versions = new HashSet<>();
        for (KeyProvider delegate : delegates) {
            versions.addAll(delegate.getAvailableVersions());
        }
        return Collections.unmodifiableSet(versions);
    }
}
