// ElGamal Cryptosystem - Educational Implementation
// Public-key encryption based on Diffie-Hellman key exchange
// Security relies on the difficulty of the Discrete Logarithm Problem (DLP)

// Modular exponentiation: (base^exp) mod m
// Uses square-and-multiply algorithm for efficiency
function modPow(base, exp, m) {
  if (m === 1n) return 0n;
  let result = 1n;
  base = base % m;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp / 2n;
    base = (base * base) % m;
  }
  return result;
}

// Extended Euclidean Algorithm to find modular inverse
// Returns x such that (a * x) mod m = 1
function modInverse(a, m) {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  
  if (old_r !== 1n) return null; // No inverse exists
  return ((old_s % m) + m) % m;
}

// Simple primality test (trial division - for small primes only)
function isPrime(n) {
  if (n < 2n) return false;
  if (n === 2n) return true;
  if (n % 2n === 0n) return false;
  for (let i = 3n; i * i <= n; i += 2n) {
    if (n % i === 0n) return false;
  }
  return true;
}

// Generate a random BigInt in range [min, max)
function randomBigInt(min, max) {
  const range = max - min;
  const bits = range.toString(2).length;
  let result;
  do {
    let hex = '';
    for (let i = 0; i < Math.ceil(bits / 4); i++) {
      hex += Math.floor(Math.random() * 16).toString(16);
    }
    result = BigInt('0x' + hex) % range;
  } while (result < 0n);
  return min + result;
}

// Find a primitive root (generator) modulo p
// For a prime p, g is a primitive root if g generates all elements of Z*_p
function findPrimitiveRoot(p) {
  if (p === 2n) return 1n;
  
  // For safe prime p = 2q + 1 where q is also prime
  // g is a primitive root if g^2 ≠ 1 (mod p) and g^q ≠ 1 (mod p)
  const q = (p - 1n) / 2n;
  
  for (let g = 2n; g < p; g++) {
    if (modPow(g, 2n, p) !== 1n && modPow(g, q, p) !== 1n) {
      return g;
    }
  }
  return 2n; // Fallback
}

// Pre-defined safe primes for educational use
// Safe prime: p = 2q + 1 where q is also prime
const SAFE_PRIMES = [
  467n,    // Small for quick demos
  1019n,   // Slightly larger
  2027n,   // Medium
  4079n,   // Larger demo
  7919n    // Even larger
];

// Generate ElGamal key pair
// Parameters:
//   p: large prime (defines the group Z*_p)
//   g: primitive root modulo p (generator)
//   x: private key (random integer in [2, p-2])
//   y: public key = g^x mod p
function generateKeys(primeIndex = 0) {
  // Select a safe prime
  const p = SAFE_PRIMES[primeIndex % SAFE_PRIMES.length];
  
  // Find a primitive root (generator)
  const g = findPrimitiveRoot(p);
  
  // Generate private key x: random in [2, p-2]
  const x = randomBigInt(2n, p - 1n);
  
  // Compute public key y = g^x mod p
  const y = modPow(g, x, p);
  
  return {
    publicKey: {
      p: p,    // Prime modulus
      g: g,    // Generator
      y: y     // g^x mod p
    },
    privateKey: {
      x: x     // Secret exponent
    },
    parameters: {
      p: p,
      g: g
    }
  };
}

// Encrypt a message using ElGamal
// Input: 
//   message: integer m where 0 < m < p
//   publicKey: { p, g, y }
// Output:
//   ciphertext: { c1, c2 } where:
//     c1 = g^k mod p
//     c2 = m * y^k mod p
//   (k is a random ephemeral key)
function encrypt(message, publicKey) {
  const { p, g, y } = publicKey;
  const m = BigInt(message);
  
  // Validate message range
  if (m <= 0n || m >= p) {
    throw new Error(`Message must be in range (0, ${p})`);
  }
  
  // Generate random ephemeral key k in [2, p-2]
  const k = randomBigInt(2n, p - 1n);
  
  // Compute c1 = g^k mod p (shared secret hint)
  const c1 = modPow(g, k, p);
  
  // Compute c2 = m * y^k mod p (encrypted message)
  // y^k = (g^x)^k = g^(xk) - this is the shared secret
  const s = modPow(y, k, p);  // Shared secret
  const c2 = (m * s) % p;
  
  return { c1, c2 };
}

// Decrypt a ciphertext using ElGamal
// Input:
//   ciphertext: { c1, c2 }
//   privateKey: { x }
//   publicKey: { p } (for modulus)
// Output:
//   plaintext message m
// 
// Decryption formula:
//   s = c1^x mod p (recover shared secret)
//   m = c2 * s^(-1) mod p
function decrypt(ciphertext, privateKey, publicKey) {
  const { c1, c2 } = ciphertext;
  const { x } = privateKey;
  const { p } = publicKey;
  
  // Compute shared secret s = c1^x mod p
  // c1 = g^k, so c1^x = g^(kx) = y^k = s
  const s = modPow(c1, x, p);
  
  // Compute modular inverse of s
  const sInverse = modInverse(s, p);
  
  // Recover message: m = c2 * s^(-1) mod p
  const m = (c2 * sInverse) % p;
  
  return m;
}

// Encrypt a string message (converts to array of encrypted integers)
function encryptString(plaintext, publicKey) {
  const { p } = publicKey;
  const maxChar = Number(p) - 1;
  
  // Encrypt each character as its ASCII code
  const encrypted = [];
  for (const char of plaintext) {
    const charCode = char.charCodeAt(0);
    if (charCode >= maxChar) {
      throw new Error(`Character code ${charCode} exceeds max value ${maxChar}`);
    }
    encrypted.push(encrypt(BigInt(charCode), publicKey));
  }
  
  return encrypted;
}

// Decrypt an array of ciphertexts back to string
function decryptString(ciphertextArray, privateKey, publicKey) {
  let plaintext = '';
  for (const ct of ciphertextArray) {
    const charCode = decrypt(ct, privateKey, publicKey);
    plaintext += String.fromCharCode(Number(charCode));
  }
  return plaintext;
}

// Convert keys to string representation for display
function keysToString(keys) {
  return {
    publicKey: `(p=${keys.publicKey.p}, g=${keys.publicKey.g}, y=${keys.publicKey.y})`,
    privateKey: `(x=${keys.privateKey.x})`,
    parameters: `(p=${keys.parameters.p}, g=${keys.parameters.g})`
  };
}

module.exports = {
  generateKeys,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  keysToString,
  modPow,
  modInverse
};

// Example usage:
// const elgamal = require('./elgamal');
// 
// // Generate key pair
// const keys = elgamal.generateKeys();
// console.log('Public Key:', keys.publicKey);
// console.log('Private Key:', keys.privateKey);
// 
// // Encrypt a number
// const message = 42n;
// const ciphertext = elgamal.encrypt(message, keys.publicKey);
// console.log('Ciphertext:', ciphertext);
// 
// // Decrypt
// const decrypted = elgamal.decrypt(ciphertext, keys.privateKey, keys.publicKey);
// console.log('Decrypted:', decrypted);  // 42n
// 
// // Encrypt a string
// const encrypted = elgamal.encryptString('HELLO', keys.publicKey);
// const decryptedStr = elgamal.decryptString(encrypted, keys.privateKey, keys.publicKey);
// console.log('Decrypted string:', decryptedStr);  // HELLO
