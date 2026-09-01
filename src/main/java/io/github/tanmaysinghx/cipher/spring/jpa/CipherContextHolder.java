package io.github.tanmaysinghx.cipher.spring.jpa;

import io.github.tanmaysinghx.cipher.spring.service.CipherService;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Internal static bridge allowing JPA AttributeConverters to access the Spring-managed {@link CipherService}
 * when instantiated directly by the JPA persistence provider.
 */
public final class CipherContextHolder {

    private static final AtomicReference<CipherService> CIPHER_SERVICE_REF = new AtomicReference<>();

    private CipherContextHolder() {
        // Static holder
    }

    public static void setCipherService(CipherService cipherService) {
        CIPHER_SERVICE_REF.set(cipherService);
    }

    public static CipherService getCipherService() {
        CipherService service = CIPHER_SERVICE_REF.get();
        if (service == null) {
            throw new IllegalStateException("CipherService is not initialized in CipherContextHolder. " +
                    "Ensure CipherAutoConfiguration is enabled in the Spring ApplicationContext.");
        }
        return service;
    }

    public static void clear() {
        CIPHER_SERVICE_REF.set(null);
    }
}
