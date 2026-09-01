# Cipher Spring Boot Starter

Enterprise-grade, cryptographically secure Spring Boot starter for field-level encryption, transparent JPA column persistence, Jackson REST serialization/deserialization, Spring AOP method encryption, searchable blind indexing, and zero-downtime key rotation.

---

## What Does This Starter Encrypt & Protect?

1. **Database Columns (JPA / Hibernate)**: Transparent column encryption/decryption via `EncryptedStringAttributeConverter` and `EncryptedBytesAttributeConverter`.
2. **REST APIs & JSON DTOs (Jackson)**: Field-level encryption on API responses and decryption on incoming requests via `@EncryptedField` and `CipherJacksonModule`.
3. **Service-Layer Methods & Parameters (Spring AOP)**: Declarative method return encryption with `@EncryptResult`, return decryption with `@DecryptResult`, and parameter decryption with `@DecryptParam`.
4. **Searchable Encrypted Columns (Blind Indexing)**: Deterministic HMAC-SHA256 blind indexing via `BlindIndexService` (enabling SQL queries like `WHERE ssn_bidx = :bidx`).
5. **Programmatic Data**: Direct encryption, decryption, and batch key migration via `CipherService`.
6. **Passwords & Blind Tokens**: Memory-hard hashing via `Argon2Hasher` (Argon2id) and constant-time `HmacSigner`.
7. **External Cloud KMS / Vault Integration**: Extensible `KmsKeyProvider` SPI with `CompositeKeyProvider` and `CachedKeyProvider` (TTL caching).
8. **Observability & Liveness**: Spring Boot Actuator `CipherHealthIndicator` (`/actuator/health`) and native Micrometer telemetry.

---

## Quick Start

### 1. Add Dependency

```xml
<dependency>
    <groupId>io.github.tanmaysinghx</groupId>
    <artifactId>cipher-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### 2. Configuration (`application.yml`)

```yaml
cipher:
  enabled: true
  algorithm: AES_256_GCM
  active-key-version: v2
  keys:
    v1: "base64-or-hex-encoded-32-byte-secret-key-1"
    v2: "base64-or-hex-encoded-32-byte-secret-key-2"
  payload-prefix: "enc"
  blind-index:
    enabled: true
    secret-key: "base64-or-hex-encoded-32-byte-pepper-key"
```

---

## Enterprise Usage Patterns

### Pattern 1: JPA Entity Column Encryption & Searchable Blind Index
```java
@Entity
@Table(name = "customers")
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Encrypted with randomized AES-GCM (produces different ciphertext every save)
    @Convert(converter = EncryptedStringAttributeConverter.class)
    @Column(name = "ssn")
    private String ssn;

    // Deterministic Blind Index for fast querying: WHERE ssn_bidx = :bidx
    @Column(name = "ssn_bidx", length = 64, index = true)
    private String ssnBidx;

    // getters, setters...
}
```

### Pattern 2: REST DTO Field-Level Encryption (Jackson)
```java
public record UserRegistrationRequest(
    String username,
    @EncryptedField String socialSecurityNumber,
    @EncryptedField String creditCardNumber
) {}
```

### Pattern 3: Declarative Service Method & Parameter AOP
```java
@Service
public class PaymentGatewayService {

    // Automatically decrypts incoming encrypted parameter
    public void processPayment(@DecryptParam String encryptedCardNumber) {
        // card number is already plain text here
    }

    // Automatically encrypts method return value
    @EncryptResult
    public String issueSecureToken(String accountId) {
        return "tok_" + UUID.randomUUID();
    }
}
```

### Pattern 4: Programmatic API & Key Migration
```java
@Service
public class DataMigrationService {

    private final CipherService cipherService;

    public DataMigrationService(CipherService cipherService) {
        this.cipherService = cipherService;
    }

    // Re-encrypts ciphertext created with an older key version to the current active key
    public String migrateLegacyCiphertext(String oldCiphertext) {
        return cipherService.reEncrypt(oldCiphertext);
    }
}
```

---

## Build & Verification

```bash
mvn clean test
```
# cipher-spring-boot-starter
