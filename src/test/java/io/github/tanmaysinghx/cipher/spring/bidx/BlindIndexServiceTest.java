package io.github.tanmaysinghx.cipher.spring.bidx;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

class BlindIndexServiceTest {

    private DefaultBlindIndexService blindIndexService;

    @BeforeEach
    void setUp() {
        byte[] pepper = new byte[32];
        new SecureRandom().nextBytes(pepper);
        blindIndexService = new DefaultBlindIndexService(pepper);
    }

    @Test
    @DisplayName("Given same plaintext, blind index produces deterministic output for database querying")
    void shouldProduceDeterministicBlindIndex() {
        String ssn = "123-45-6789";

        String bidx1 = blindIndexService.compute(ssn);
        String bidx2 = blindIndexService.compute(ssn);

        assertThat(bidx1).isEqualTo(bidx2);
        assertThat(bidx1).startsWith("bidx:");
        assertThat(blindIndexService.verify(ssn, bidx1)).isTrue();
        assertThat(blindIndexService.verify("999-99-9999", bidx1)).isFalse();
    }

    @Test
    @DisplayName("Given same plaintext with different column contexts, blind indices are distinct preventing correlation")
    void shouldIsolateContexts() {
        String sharedValue = "admin@example.com";

        String userEmailIndex = blindIndexService.compute(sharedValue, "user.email");
        String auditEmailIndex = blindIndexService.compute(sharedValue, "audit.email");

        assertThat(userEmailIndex).isNotEqualTo(auditEmailIndex);
    }
}
