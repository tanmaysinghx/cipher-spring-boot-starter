package io.github.tanmaysinghx.cipher.spring.aop;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation on service methods instructing Spring AOP to automatically encrypt the method return value.
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface EncryptResult {

    /**
     * Optional key version override.
     */
    String keyVersion() default "";
}
