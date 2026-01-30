# Public-Key Cryptography

Educational implementations of ElGamal and Elliptic Curve Cryptography (ECC).

## ElGamal Cryptosystem

Based on the Discrete Logarithm Problem (DLP) over integers modulo a prime.

### Key Structure

```javascript
{
  publicKey: { p, g, y },      // p: prime, g: generator, y = g^x mod p
  privateKey: { x },           // Secret exponent
  parameters: { p, g }
}
```

### Usage

```javascript
const elgamal = require('./elgamal');

// Generate keys (primeIndex 0-4 for different prime sizes)
const keys = elgamal.generateKeys(0);

// Encrypt/decrypt a number
const ciphertext = elgamal.encrypt(42n, keys.publicKey);
const plaintext = elgamal.decrypt(ciphertext, keys.privateKey, keys.publicKey);

// Encrypt/decrypt a string
const encrypted = elgamal.encryptString('HELLO', keys.publicKey);
const decrypted = elgamal.decryptString(encrypted, keys.privateKey, keys.publicKey);
```

## Elliptic Curve Cryptography (ECC)

Uses small curves over finite fields: y² = x³ + ax + b (mod p)

### Available Curves

| Curve | Equation | Prime | Use |
|-------|----------|-------|-----|
| `CURVE_TINY` | y² = x³ + x + 6 | 11 | Step-by-step learning |
| `CURVE_SMALL` | y² = x³ + 2x + 3 | 97 | Quick demos (default) |
| `CURVE_SECP_LIKE` | y² = x³ + 7 | 17 | secp256k1 structure |

### Key Structure

```javascript
{
  publicKey: { Q, curve },     // Q = d * G (point on curve)
  privateKey: { d },           // Secret scalar
  parameters: { a, b, p, G, n }
}
```

### Usage

```javascript
const ecc = require('./ecc');
const curve = ecc.CURVE_SMALL;

// Generate keys
const keys = ecc.generateKeys(curve);

// ECDH Key Agreement
const alice = ecc.generateKeys(curve);
const bob = ecc.generateKeys(curve);
const aliceShared = ecc.ecdhSharedSecret(alice.privateKey, bob.publicKey, curve);
const bobShared = ecc.ecdhSharedSecret(bob.privateKey, alice.publicKey, curve);
// aliceShared === bobShared (same point!)

// Encrypt/decrypt a small integer
const encrypted = ecc.encrypt(5n, keys.publicKey, curve);
const decrypted = ecc.decrypt(encrypted, keys.privateKey, curve);
```

## ⚠️ Educational Use Only

These implementations use small parameters for clarity. They are **NOT secure** for production use.
