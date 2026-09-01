package io.github.tanmaysinghx.cipher.spring.jpa;

import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * Transparent JPA {@link AttributeConverter} encrypting entity String fields into database columns.
 */
@Converter
public class EncryptedStringAttributeConverter implements AttributeConverter<String, String> {

    private final CipherService cipherService;

    public EncryptedStringAttributeConverter() {
        this(null);
    }

    public EncryptedStringAttributeConverter(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    private CipherService getService() {
        return cipherService != null ? cipherService : CipherContextHolder.getCipherService();
    }

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) {
            return null;
        }
        return getService().encrypt(attribute);
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) {
            return dbData;
        }
        CipherService service = getService();
        if (service.isEncrypted(dbData)) {
            return service.decrypt(dbData);
        }
        return dbData;
    }
}
