# Modern Symmetric Cryptography

Educational implementations of DES and AES-128 block ciphers.

## Key Formats

| Algorithm | Key Length | Format | Example |
|-----------|------------|--------|---------|
| **DES** | 64-bit | 16 hex characters | `133457799BBCDFF1` |
| **AES-128** | 128-bit | 32 hex characters | `2b7e151628aed2a6abf7158809cf4f3c` |

## Usage

```javascript
// DES
const des = require('./des');
const desKey = '133457799BBCDFF1';  // 16 hex chars = 64 bits
const encrypted = des.encrypt('HELLO', desKey);
const decrypted = des.decrypt(encrypted, desKey);

// AES-128
const aes = require('./aes');
const aesKey = '2b7e151628aed2a6abf7158809cf4f3c';  // 32 hex chars = 128 bits
const encrypted = aes.encrypt('HELLO', aesKey);
const decrypted = aes.decrypt(encrypted, aesKey);
```

## Notes

- These implementations are for **educational purposes only**
- Input: plaintext string, Output: hexadecimal ciphertext
- Both use PKCS#7 padding for messages not aligned to block size
