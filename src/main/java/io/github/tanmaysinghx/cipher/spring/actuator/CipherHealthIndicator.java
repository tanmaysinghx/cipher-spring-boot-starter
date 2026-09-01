package io.github.tanmaysinghx.cipher.spring.actuator;

import io.github.tanmaysinghx.cipher.core.key.KeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

import java.util.Objects;
import java.util.Set;

/**
 * Spring Boot Actuator {@link HealthIndicator} verifying cryptographic service integrity and active key readiness.
 */
public class CipherHealthIndicator implements HealthIndicator {

    private final CipherService cipherService;
    private final KeyProvider keyProvider;

    public CipherHealthIndicator(CipherService cipherService, KeyProvider keyProvider) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
        this.keyProvider = Objects.requireNonNull(keyProvider, "KeyProvider must not be null");
    }

    @Override
    public Health health() {
        try {
            SecretKeyHolder activeKey = keyProvider.getActiveKey();
            if (activeKey == null || activeKey.isDestroyed()) {
                return Health.down().withDetail("error", "Active key is null or destroyed").build();
            }

            Set<String> availableVersions = keyProvider.getAvailableVersions();

            // Perform a quick self-test roundtrip
            String probe = "cipher-health-probe";
            String encrypted = cipherService.encrypt(probe);
            String decrypted = cipherService.decrypt(encrypted);

            if (!probe.equals(decrypted)) {
                return Health.down()
                        .withDetail("error", "Self-test roundtrip validation failed")
                        .build();
            }

            return Health.up()
                    .withDetail("status", "READY")
                    .withDetail("activeKeyVersion", activeKey.getVersion())
                    .withDetail("algorithm", activeKey.getAlgorithm().name())
                    .withDetail("keySizeBits", activeKey.getAlgorithm().getKeySizeBits())
                    .withDetail("availableVersions", availableVersions)
                    .build();
        } catch (Exception e) {
            return Health.down(e)
                    .withDetail("error", e.getMessage())
                    .build();
        }
    }
}
