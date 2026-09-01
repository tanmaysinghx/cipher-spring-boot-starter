package io.github.tanmaysinghx.cipher.spring.jackson;

import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.NopAnnotationIntrospector;
import io.github.tanmaysinghx.cipher.spring.annotation.EncryptedField;
import io.github.tanmaysinghx.cipher.spring.service.CipherService;

import java.util.Objects;

/**
 * Custom Jackson AnnotationIntrospector that automatically attaches cipher serializers and deserializers
 * to fields and accessors annotated with {@link EncryptedField}.
 */
public class CipherAnnotationIntrospector extends NopAnnotationIntrospector {

    private static final long serialVersionUID = 1L;
    private final transient CipherService cipherService;

    public CipherAnnotationIntrospector(CipherService cipherService) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
    }

    @Override
    public Object findSerializer(Annotated a) {
        EncryptedField annotation = a.getAnnotation(EncryptedField.class);
        if (annotation != null) {
            return new EncryptedJsonSerializer(cipherService, annotation.keyVersion());
        }
        return super.findSerializer(a);
    }

    @Override
    public Object findDeserializer(Annotated a) {
        EncryptedField annotation = a.getAnnotation(EncryptedField.class);
        if (annotation != null) {
            return new DecryptedJsonDeserializer(cipherService);
        }
        return super.findDeserializer(a);
    }
}
