package io.github.tanmaysinghx.cipher.spring.aop;

import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Objects;

/**
 * Spring AOP Aspect providing declarative method-level and parameter-level encryption and decryption.
 */
@Aspect
public class CipherAspect {

    private final CipherService cipherService;

    public CipherAspect(CipherService cipherService) {
        this.cipherService = Objects.requireNonNull(cipherService, "CipherService must not be null");
    }

    @Around("@annotation(io.github.tanmaysinghx.cipher.spring.aop.EncryptResult) || " +
            "@annotation(io.github.tanmaysinghx.cipher.spring.aop.DecryptResult) || " +
            "execution(* *(.., @io.github.tanmaysinghx.cipher.spring.aop.DecryptParam (*), ..))")
    public Object handleCipherAdvice(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();
        Class<?> targetClass = (joinPoint.getTarget() != null) ? joinPoint.getTarget().getClass() : signature.getDeclaringType();
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);

        Object[] args = joinPoint.getArgs();

        // 1. Process parameter decryption for @DecryptParam
        Annotation[][] paramAnnotations = specificMethod.getParameterAnnotations();
        boolean argsModified = false;

        for (int i = 0; i < args.length; i++) {
            if (args[i] instanceof String strVal && (hasAnnotation(paramAnnotations[i], DecryptParam.class) || (i < method.getParameterAnnotations().length && hasAnnotation(method.getParameterAnnotations()[i], DecryptParam.class)))) {
                if (cipherService.isEncrypted(strVal)) {
                    args[i] = cipherService.decrypt(strVal);
                    argsModified = true;
                }
            }
        }

        Object result = argsModified ? joinPoint.proceed(args) : joinPoint.proceed();

        // 2. Process return value encryption for @EncryptResult
        EncryptResult encryptResult = AnnotatedElementUtils.findMergedAnnotation(specificMethod, EncryptResult.class);
        if (encryptResult == null) {
            encryptResult = AnnotatedElementUtils.findMergedAnnotation(method, EncryptResult.class);
        }

        if (encryptResult != null && result instanceof String plainReturn) {
            String keyVersion = encryptResult.keyVersion();
            return (keyVersion.isBlank())
                    ? cipherService.encrypt(plainReturn)
                    : cipherService.encrypt(plainReturn, keyVersion);
        }

        // 3. Process return value decryption for @DecryptResult
        DecryptResult decryptResult = AnnotatedElementUtils.findMergedAnnotation(specificMethod, DecryptResult.class);
        if (decryptResult == null) {
            decryptResult = AnnotatedElementUtils.findMergedAnnotation(method, DecryptResult.class);
        }

        if (decryptResult != null && result instanceof String encryptedReturn) {
            if (cipherService.isEncrypted(encryptedReturn)) {
                return cipherService.decrypt(encryptedReturn);
            }
        }

        return result;
    }

    private boolean hasAnnotation(Annotation[] annotations, Class<? extends Annotation> target) {
        if (annotations == null) return false;
        for (Annotation a : annotations) {
            if (target.isInstance(a)) {
                return true;
            }
        }
        return false;
    }
}
