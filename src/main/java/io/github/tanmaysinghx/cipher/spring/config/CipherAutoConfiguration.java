package io.github.tanmaysinghx.cipher.spring.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.tanmaysinghx.cipher.core.algorithm.CipherAlgorithm;
import io.github.tanmaysinghx.cipher.core.engine.AesGcmCipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.ChaCha20Poly1305CipherEngine;
import io.github.tanmaysinghx.cipher.core.engine.CipherEngine;
import io.github.tanmaysinghx.cipher.core.exception.InvalidKeyException;
import io.github.tanmaysinghx.cipher.core.format.CompactPayloadFormatter;
import io.github.tanmaysinghx.cipher.core.format.PayloadFormatter;
import io.github.tanmaysinghx.cipher.core.key.CompositeKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.KeyProvider;
import io.github.tanmaysinghx.cipher.core.key.KmsKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.MapKeyProvider;
import io.github.tanmaysinghx.cipher.core.key.SecretKeyHolder;
import io.github.tanmaysinghx.cipher.spring.actuator.CipherHealthIndicator;
import io.github.tanmaysinghx.cipher.spring.aop.CipherAspect;
import io.github.tanmaysinghx.cipher.spring.bidx.BlindIndexService;
import io.github.tanmaysinghx.cipher.spring.bidx.DefaultBlindIndexService;
import io.github.tanmaysinghx.cipher.spring.jackson.CipherJacksonModule;
import io.github.tanmaysinghx.cipher.spring.jpa.CipherContextHolder;
import io.github.tanmaysinghx.cipher.spring.metrics.CipherMetrics;
import io.github.tanmaysinghx.cipher.spring.metrics.MicrometerCipherMetrics;
import io.github.tanmaysinghx.cipher.spring.metrics.NoOpCipherMetrics;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import io.github.tanmaysinghx.cipher.spring.service.DefaultCipherService;
import io.micrometer.core.instrument.MeterRegistry;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Enterprise Spring Boot AutoConfiguration for the Cipher Starter.
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "cipher", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(CipherProperties.class)
public class CipherAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(CipherAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public PayloadFormatter cipherPayloadFormatter(CipherProperties properties) {
        return new CompactPayloadFormatter(properties.getPayloadPrefix());
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyProvider cipherKeyProvider(
            CipherProperties properties,
            ObjectProvider<List<KmsKeyProvider>> kmsProvidersProvider
    ) {
        Map<String, SecretKeyHolder> holders = new HashMap<>();
        CipherAlgorithm defaultAlgorithm = properties.getAlgorithm();

        if (properties.getKeys() != null) {
            for (Map.Entry<String, String> entry : properties.getKeys().entrySet()) {
                String version = entry.getKey();
                String rawSecret = entry.getValue();
                byte[] keyBytes = decodeKeySecret(rawSecret);
                holders.put(version, new SecretKeyHolder(version, defaultAlgorithm, keyBytes));
            }
        }

        List<KeyProvider> providerList = new ArrayList<>();
        if (!holders.isEmpty()) {
            providerList.add(new MapKeyProvider(properties.getActiveKeyVersion(), holders));
        }

        List<KmsKeyProvider> kmsProviders = kmsProvidersProvider.getIfAvailable();
        if (kmsProviders != null && !kmsProviders.isEmpty()) {
            providerList.addAll(kmsProviders);
        }

        if (providerList.isEmpty()) {
            throw new InvalidKeyException("No cryptographic keys configured. Provide cipher.keys or a KmsKeyProvider bean.");
        }

        if (providerList.size() == 1) {
            return providerList.getFirst();
        }

        log.info("Configured CompositeKeyProvider with {} delegates.", providerList.size());
        return new CompositeKeyProvider(providerList);
    }

    @Bean
    @ConditionalOnMissingBean(name = "aes256GcmCipherEngine")
    public CipherEngine aes256GcmCipherEngine() {
        return new AesGcmCipherEngine(CipherAlgorithm.AES_256_GCM);
    }

    @Bean
    @ConditionalOnMissingBean(name = "aes128GcmCipherEngine")
    public CipherEngine aes128GcmCipherEngine() {
        return new AesGcmCipherEngine(CipherAlgorithm.AES_128_GCM);
    }

    @Bean
    @ConditionalOnMissingBean(name = "chaCha20Poly1305CipherEngine")
    public CipherEngine chaCha20Poly1305CipherEngine() {
        return new ChaCha20Poly1305CipherEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    public CipherMetrics cipherMetrics(ObjectProvider<MeterRegistry> meterRegistryProvider) {
        MeterRegistry meterRegistry = meterRegistryProvider.getIfAvailable();
        if (meterRegistry != null) {
            return new MicrometerCipherMetrics(meterRegistry);
        }
        return new NoOpCipherMetrics();
    }

    @Bean
    @ConditionalOnMissingBean
    public CipherService cipherService(
            List<CipherEngine> availableEngines,
            KeyProvider keyProvider,
            PayloadFormatter payloadFormatter,
            CipherMetrics metrics
    ) {
        Map<String, CipherEngine> enginesMap = availableEngines.stream()
                .collect(Collectors.toMap(engine -> engine.getAlgorithm().name(), Function.identity()));

        DefaultCipherService cipherService = new DefaultCipherService(enginesMap, keyProvider, payloadFormatter, metrics);
        CipherContextHolder.setCipherService(cipherService);
        return cipherService;
    }

    @Bean
    @ConditionalOnClass(ObjectMapper.class)
    @ConditionalOnMissingBean
    public CipherJacksonModule cipherJacksonModule(CipherService cipherService) {
        return new CipherJacksonModule(cipherService);
    }

    @Bean
    @ConditionalOnClass(Aspect.class)
    @ConditionalOnMissingBean
    public CipherAspect cipherAspect(CipherService cipherService) {
        return new CipherAspect(cipherService);
    }

    @Bean
    @ConditionalOnClass(HealthIndicator.class)
    @ConditionalOnMissingBean(name = "cipherHealthIndicator")
    public CipherHealthIndicator cipherHealthIndicator(CipherService cipherService, KeyProvider keyProvider) {
        return new CipherHealthIndicator(cipherService, keyProvider);
    }

    @Bean
    @ConditionalOnProperty(prefix = "cipher.blind-index", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public BlindIndexService blindIndexService(CipherProperties properties) {
        String secret = properties.getBlindIndex().getSecretKey();
        if (secret == null || secret.isBlank()) {
            throw new InvalidKeyException("cipher.blind-index.secret-key must be provided when blind indexing is enabled");
        }
        byte[] pepper = decodeKeySecret(secret);
        return new DefaultBlindIndexService(pepper);
    }

    private static byte[] decodeKeySecret(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new InvalidKeyException("Secret key value cannot be null or blank");
        }
        String clean = secret.trim();
        try {
            return Base64.getDecoder().decode(clean);
        } catch (IllegalArgumentException base64Ex) {
            try {
                return HexFormat.of().parseHex(clean);
            } catch (IllegalArgumentException hexEx) {
                throw new InvalidKeyException("Failed to decode secret key as Base64 or Hex. Ensure valid encoding.");
            }
        }
    }
}
