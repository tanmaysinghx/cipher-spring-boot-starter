package io.github.tanmaysinghx.cipher.spring.aop;

import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;

import java.security.SecureRandom;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CipherAspectTest {

    public static class SampleService {
        public String processSecret(@DecryptParam String encryptedInput) {
            return "PROCESSED:" + encryptedInput;
        }

        @EncryptResult
        public String generateEncryptedToken(String rawToken) {
            return rawToken;
        }

        @DecryptResult
        public String fetchDecryptedToken(String encryptedToken) {
            return encryptedToken;
        }
    }

    private DefaultCipherService cipherService;
    private SampleService proxiedService;

    @BeforeEach
    void setUp() {
        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKeyHolder keyHolder = new SecretKeyHolder("v1", CipherAlgorithm.AES_256_GCM, keyBytes);

        MapKeyProvider keyProvider = new MapKeyProvider("v1", Map.of("v1", keyHolder));
        Map<String, CipherEngine> engines = Map.of(
                CipherAlgorithm.AES_256_GCM.name(), new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM)
        );
        cipherService = new DefaultCipherService(engines, keyProvider, new CompactPayloadFormatter());

        CipherAspect aspect = new CipherAspect(cipherService);
        ProxyFactory factory = new ProxyFactory(new SampleService());
        factory.addAdvice((org.aopalliance.intercept.MethodInterceptor) invocation -> {
            // Adapt AOP Alliance MethodInvocation to ProceedingJoinPoint via Spring Aop
            return aspect.handleCipherAdvice(new org.springframework.aop.aspectj.MethodInvocationProceedingJoinPoint(
                    (org.springframework.aop.framework.ReflectiveMethodInvocation) invocation
            ));
        });
        proxiedService = (SampleService) factory.getProxy();
    }

    @Test
    @DisplayName("Given @DecryptParam on method argument, incoming encrypted string is automatically decrypted")
    void shouldDecryptParameterDeclaratively() {
        String secret = "SuperSecretBankToken";
        String encrypted = cipherService.encrypt(secret);

        String result = proxiedService.processSecret(encrypted);

        assertThat(result).isEqualTo("PROCESSED:SuperSecretBankToken");
    }

    @Test
    @DisplayName("Given @EncryptResult on method, returned plaintext is automatically encrypted")
    void shouldEncryptReturnDeclaratively() {
        String rawToken = "ApiKey-12345";

        String encryptedResult = proxiedService.generateEncryptedToken(rawToken);

        assertThat(encryptedResult).startsWith("enc:v1:");
        assertThat(cipherService.decrypt(encryptedResult)).isEqualTo(rawToken);
    }

    @Test
    @DisplayName("Given @DecryptResult on method, returned ciphertext is automatically decrypted")
    void shouldDecryptReturnDeclaratively() {
        String original = "DatabaseEncryptedSecret";
        String encrypted = cipherService.encrypt(original);

        String decryptedResult = proxiedService.fetchDecryptedToken(encrypted);

        assertThat(decryptedResult).isEqualTo(original);
    }
}
