package io.github.tanmaysinghx.cipher.spring.jpa;

import io.github.tanmaysinghx.cipher.spring.service.CipherService;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.nio.charset.StandardCharsets;

/**
 * Transparent JPA {@link AttributeConverter} encrypting entity byte[] fields into database columns.
 */
@Converter
public class EncryptedBytesAttributeConverter implements AttributeConverter<byte[], byte[]> {

    private final CipherService cipherService;

    public EncryptedBytesAttributeConverter() {
        this(null);
    }

    public EncryptedBytesAttributeConverter(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    private CipherService getService() {
        return cipherService != null ? cipherService : CipherContextHolder.getCipherService();
    }

    @Override
    public byte[] convertToDatabaseColumn(byte[] attribute) {
        if (attribute == null) {
            return null;
        }
        return getService().encryptBytes(attribute);
    }

    @Override
    public byte[] convertToEntityAttribute(byte[] dbData) {
        if (dbData == null || dbData.length == 0) {
            return dbData;
        }
        String text = new String(dbData, StandardCharsets.UTF_8);
        CipherService service = getService();
        if (service.isEncrypted(text)) {
            return service.decryptBytes(dbData);
        }
        return dbData;
    }
}
