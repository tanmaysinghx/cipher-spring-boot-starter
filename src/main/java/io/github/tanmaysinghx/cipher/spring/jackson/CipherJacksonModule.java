package io.github.tanmaysinghx.cipher.spring.jackson;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.introspect.AnnotationIntrospectorPair;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;

import java.util.Objects;

/**
 * Jackson Module registering the {@link CipherAnnotationIntrospector} for transparent JSON encryption/decryption.
 */
public class CipherJacksonModule extends Module {

    private final CipherService cipherService;

    public CipherJacksonModule(CipherService cipherService) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
    }

    @Override
    public String getModuleName() {
        return "CipherJacksonModule";
    }

    @Override
    public Version version() {
        return new Version(1, 0, 0, null, "io.github.tanmaysinghx", "cipher-spring-boot-starter");
    }

    @Override
    public void setupModule(SetupContext context) {
        CipherAnnotationIntrospector introspector = new CipherAnnotationIntrospector(cipherService);
        context.insertAnnotationIntrospector(introspector);
    }
}
