package io.github.tanmaysinghx.cipher.spring.config;

import io.github.tanmaysinghx.cipher.core.format.PayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.KeyProvider;
import io.github.tanmaysinghx.cipher.spring.jackson.CipherJacksonModule;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class CipherAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CipherAutoConfiguration.class));

    private final String validBase64Key256 = Base64.getEncoder().encodeToString(new byte[32]);

    @Test
    @DisplayName("Given valid properties, auto-configuration initializes all cipher beans")
    void shouldInitializeAllBeansWithValidProperties() {
        contextRunner
                .withPropertyValues(
                        "cipher.enabled=true",
                        "cipher.active-key-version=v1",
                        "cipher.algorithm=AES_256_GCM",
                        "cipher.keys.v1=" + validBase64Key256
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(CipherProperties.class);
                    assertThat(context).hasSingleBean(KeyProvider.class);
                    assertThat(context).hasSingleBean(PayloadFormatter.class);
                    assertThat(context).hasSingleBean(CipherService.class);
                    assertThat(context).hasSingleBean(CipherJacksonModule.class);

                    CipherService cipherService = context.getBean(CipherService.class);
                    String plaintext = "Hello Spring Boot 3!";
                    String encrypted = cipherService.encrypt(plaintext);
                    assertThat(encrypted).startsWith("enc:v1:");
                    assertThat(cipherService.decrypt(encrypted)).isEqualTo(plaintext);
                });
    }

    @Test
    @DisplayName("Given cipher.enabled=false, auto-configuration does not register beans")
    void shouldNotLoadBeansWhenDisabled() {
        contextRunner
                .withPropertyValues("cipher.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(CipherService.class);
                    assertThat(context).doesNotHaveBean(KeyProvider.class);
                });
    }
}
