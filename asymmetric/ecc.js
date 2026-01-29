// Elliptic Curve Cryptography (ECC) - Educational Implementation
// Uses small curves over finite fields for demonstration
// 
// Elliptic Curve equation: y² = x³ + ax + b (mod p)
// Points on the curve form an abelian group under point addition

// Modular arithmetic helpers

// Modular inverse using Extended Euclidean Algorithm
function modInverse(a, p) {
  a = ((a % p) + p) % p;
  let [old_r, r] = [a, p];
  let [old_s, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  
  if (old_r !== 1n) return null;
  return ((old_s % p) + p) % p;
}

// Modular exponentiation
function modPow(base, exp, m) {
  if (m === 1n) return 0n;
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % m;
    }
    exp = exp / 2n;
    base = (base * base) % m;
  }
  return result;
}

// Point at infinity (identity element)
const INFINITY = { x: null, y: null };

// Check if a point is the point at infinity
function isInfinity(P) {
  return P.x === null && P.y === null;
}

// Check if two points are equal
function pointEquals(P, Q) {
  if (isInfinity(P) && isInfinity(Q)) return true;
  if (isInfinity(P) || isInfinity(Q)) return false;
  return P.x === Q.x && P.y === Q.y;
}

// Elliptic Curve class
// Curve: y² = x³ + ax + b (mod p)
class EllipticCurve {
  constructor(a, b, p, G, n) {
    this.a = BigInt(a);  // Curve parameter a
    this.b = BigInt(b);  // Curve parameter b
    this.p = BigInt(p);  // Prime field modulus
    this.G = G;          // Generator point (base point)
    this.n = BigInt(n);  // Order of the generator point
  }

  // Check if a point lies on the curve
  // Verify: y² ≡ x³ + ax + b (mod p)
  isOnCurve(P) {
    if (isInfinity(P)) return true;
    
    const { x, y } = P;
    const left = (y * y) % this.p;
    const right = ((x * x * x) + (this.a * x) + this.b) % this.p;
    return ((left - right) % this.p + this.p) % this.p === 0n;
  }

  // Point Addition: P + Q
  // Cases:
  //   1. P = O (infinity) → return Q
  //   2. Q = O (infinity) → return P
  //   3. P = -Q (same x, opposite y) → return O
  //   4. P = Q → use point doubling formula
  //   5. P ≠ Q → use standard addition formula
  add(P, Q) {
    // Case 1: P is infinity
    if (isInfinity(P)) return Q;
    
    // Case 2: Q is infinity
    if (isInfinity(Q)) return P;
    
    const { p, a } = this;
    
    // Case 3: P = -Q (points are inverses)
    if (P.x === Q.x && ((P.y + Q.y) % p === 0n)) {
      return INFINITY;
    }
    
    let lambda;
    
    if (P.x === Q.x && P.y === Q.y) {
      // Case 4: Point Doubling (P = Q)
      // λ = (3x₁² + a) / (2y₁) mod p
      const numerator = (3n * P.x * P.x + a) % p;
      const denominator = (2n * P.y) % p;
      const denominatorInv = modInverse(denominator, p);
      if (denominatorInv === null) return INFINITY;
      lambda = (numerator * denominatorInv) % p;
    } else {
      // Case 5: Point Addition (P ≠ Q)
      // λ = (y₂ - y₁) / (x₂ - x₁) mod p
      const numerator = ((Q.y - P.y) % p + p) % p;
      const denominator = ((Q.x - P.x) % p + p) % p;
      const denominatorInv = modInverse(denominator, p);
      if (denominatorInv === null) return INFINITY;
      lambda = (numerator * denominatorInv) % p;
    }
    
    // Calculate new point R = P + Q
    // x₃ = λ² - x₁ - x₂ mod p
    // y₃ = λ(x₁ - x₃) - y₁ mod p
    let x3 = (lambda * lambda - P.x - Q.x) % p;
    let y3 = (lambda * (P.x - x3) - P.y) % p;
    
    // Ensure positive modulo
    x3 = ((x3 % p) + p) % p;
    y3 = ((y3 % p) + p) % p;
    
    return { x: x3, y: y3 };
  }

  // Scalar Multiplication: k * P
  // Uses double-and-add algorithm (analogous to square-and-multiply)
  // Computes P + P + ... + P (k times)
  multiply(k, P) {
    if (k === 0n || isInfinity(P)) {
      return INFINITY;
    }
    
    if (k < 0n) {
      // Negate point: -P = (x, -y)
      k = -k;
      P = { x: P.x, y: (this.p - P.y) % this.p };
    }
    
    let result = INFINITY;
    let addend = { x: P.x, y: P.y };
    
    while (k > 0n) {
      if (k % 2n === 1n) {
        result = this.add(result, addend);
      }
      addend = this.add(addend, addend);  // Point doubling
      k = k / 2n;
    }
    
    return result;
  }

  // Get the negative of a point: -P = (x, -y mod p)
  negate(P) {
    if (isInfinity(P)) return INFINITY;
    return { x: P.x, y: (this.p - P.y) % this.p };
  }
}

// Pre-defined small elliptic curves for educational use
// These are NOT secure for real cryptography!

// Curve 1: y² = x³ + x + 1 (mod 167)
// Good curve with order 144 - handles ASCII characters well
const CURVE_SMALL = new EllipticCurve(
  1n,   // a
  1n,   // b
  167n, // p (prime)
  { x: 2n, y: 41n },  // Generator point G
  144n  // Order of G
);

// Curve 2: y² = x³ + x + 6 (mod 11)
// Very small curve for step-by-step learning (limited use)
const CURVE_TINY = new EllipticCurve(
  1n,   // a
  6n,   // b
  11n,  // p
  { x: 2n, y: 7n },  // Generator point G
  7n    // Order of G - only for very small numbers
);

// Curve 3: y² = x³ + 7 (mod 17) - similar structure to secp256k1
// a = 0, b = 7 (like Bitcoin's curve, but tiny prime)
const CURVE_SECP_LIKE = new EllipticCurve(
  0n,   // a
  7n,   // b
  17n,  // p
  { x: 15n, y: 13n },  // Generator point G
  18n   // Order of G
);

// Generate ECC key pair
// Private key: random integer d in [1, n-1]
// Public key: Q = d * G (scalar multiplication of generator)
function generateKeys(curve = CURVE_SMALL) {
  // Generate random private key d
  const d = randomBigInt(1n, curve.n);
  
  // Compute public key Q = d * G
  const Q = curve.multiply(d, curve.G);
  
  return {
    publicKey: {
      Q: Q,           // Public point
      curve: curve    // Curve parameters
    },
    privateKey: {
      d: d            // Secret scalar
    },
    parameters: {
      a: curve.a,
      b: curve.b,
      p: curve.p,
      G: curve.G,
      n: curve.n
    }
  };
}

// Generate random BigInt in range [min, max)
function randomBigInt(min, max) {
  const range = max - min;
  const bits = range.toString(2).length;
  let result;
  do {
    let hex = '';
    for (let i = 0; i < Math.ceil(bits / 4); i++) {
      hex += Math.floor(Math.random() * 16).toString(16);
    }
    result = BigInt('0x' + (hex || '0')) % range;
  } while (result < 0n);
  return min + result;
}

// ECDH Key Agreement
// Alice and Bob can compute a shared secret without exchanging it

// Step 1: Alice generates her key pair (dA, QA = dA * G)
// Step 2: Bob generates his key pair (dB, QB = dB * G)
// Step 3: Alice computes shared secret: S = dA * QB = dA * dB * G
// Step 4: Bob computes shared secret: S = dB * QA = dB * dA * G
// Both arrive at the same point S!

function ecdhSharedSecret(myPrivateKey, theirPublicKey, curve) {
  // S = d * Q (my private key × their public key)
  const sharedPoint = curve.multiply(myPrivateKey.d, theirPublicKey.Q);
  return sharedPoint;
}

// Simple ECC Encryption (ElGamal-style on elliptic curves)
// Encrypts a point M on the curve
// 
// Encryption:
//   1. Choose random k
//   2. C1 = k * G
//   3. C2 = M + k * Q (where Q is recipient's public key)
// 
// Decryption:
//   1. Compute k * Q = d * C1 (using private key d)
//   2. M = C2 - d * C1

function encryptPoint(M, publicKey, curve) {
  // Verify M is on curve
  if (!curve.isOnCurve(M)) {
    throw new Error('Message point is not on the curve');
  }
  
  const { Q } = publicKey;
  
  // Random ephemeral key k
  const k = randomBigInt(1n, curve.n);
  
  // C1 = k * G
  const C1 = curve.multiply(k, curve.G);
  
  // C2 = M + k * Q
  const kQ = curve.multiply(k, Q);
  const C2 = curve.add(M, kQ);
  
  return { C1, C2 };
}

function decryptPoint(ciphertext, privateKey, curve) {
  const { C1, C2 } = ciphertext;
  const { d } = privateKey;
  
  // Compute d * C1 = d * k * G = k * Q
  const dC1 = curve.multiply(d, C1);
  
  // M = C2 - d * C1 = C2 + (-(d * C1))
  const M = curve.add(C2, curve.negate(dC1));
  
  return M;
}

// Encode a small integer to a point on the curve (simple mapping)
// This is a naive approach for educational purposes
// Real implementations use more sophisticated encoding
function encodeToPoint(m, curve) {
  const message = BigInt(m);
  
  // Try to find a point with x = m (or nearby)
  for (let x = message; x < message + 100n; x++) {
    // Calculate y² = x³ + ax + b
    const ySquared = (x * x * x + curve.a * x + curve.b) % curve.p;
    
    // Try to find square root (Tonelli-Shanks simplified for small primes)
    for (let y = 0n; y < curve.p; y++) {
      if ((y * y) % curve.p === ySquared) {
        const point = { x: x % curve.p, y };
        if (curve.isOnCurve(point)) {
          return { point, offset: x - message };
        }
      }
    }
  }
  
  throw new Error(`Cannot encode message ${m} to curve point`);
}

// Decode a point back to integer
function decodeFromPoint(point, offset) {
  return point.x - offset;
}

// High-level encrypt/decrypt for small integers
function encrypt(message, publicKey, curve = CURVE_SMALL) {
  const { point, offset } = encodeToPoint(message, curve);
  const ciphertext = encryptPoint(point, publicKey, curve);
  return { ciphertext, offset };
}

function decrypt(encryptedData, privateKey, curve = CURVE_SMALL) {
  const { ciphertext, offset } = encryptedData;
  const point = decryptPoint(ciphertext, privateKey, curve);
  return decodeFromPoint(point, offset);
}

// String encryption - encrypts each character
function encryptString(plaintext, publicKey, curve = CURVE_SMALL) {
  const encrypted = [];
  for (const char of plaintext) {
    const m = char.charCodeAt(0);
    const { point: M, offset } = encodeToPoint(m, curve);
    
    // Find a k that doesn't produce infinity
    let k, C1, kQ, C2;
    let attempts = 0;
    do {
      k = randomBigInt(1n, curve.n - 1n);
      C1 = curve.multiply(k, curve.G);
      kQ = curve.multiply(k, publicKey.Q);
      C2 = curve.add(M, kQ);
      attempts++;
    } while ((isInfinity(C1) || isInfinity(C2)) && attempts < 100);
    
    if (isInfinity(C1) || isInfinity(C2)) {
      throw new Error('Encryption failed - curve too small for this message');
    }
    
    encrypted.push(`${C1.x},${C1.y};${C2.x},${C2.y};${offset}`);
  }
  return encrypted.join('|');
}

function decryptString(ciphertext, privateKey, curve = CURVE_SMALL) {
  const parts = ciphertext.split('|');
  let plaintext = '';
  for (const part of parts) {
    const [c1Str, c2Str, offsetStr] = part.split(';');
    const [c1x, c1y] = c1Str.split(',').map(s => BigInt(s));
    const [c2x, c2y] = c2Str.split(',').map(s => BigInt(s));
    const offset = BigInt(offsetStr);
    const C1 = { x: c1x, y: c1y };
    const C2 = { x: c2x, y: c2y };
    const dC1 = curve.multiply(privateKey.d, C1);
    const negDC1 = curve.negate(dC1);
    const M = curve.add(C2, negDC1);
    const m = M.x - offset;
    plaintext += String.fromCharCode(Number(m));
  }
  return plaintext;
}

// Generate random BigInt in range [min, max)
function randomBigInt(min, max) {
  const range = max - min;
  const bits = range.toString(2).length;
  let result;
  do {
    let hex = '';
    for (let i = 0; i < Math.ceil(bits / 4); i++) {
      hex += Math.floor(Math.random() * 16).toString(16);
    }
    result = BigInt('0x' + (hex || '0')) % range;
  } while (result < 0n);
  return min + result;
}

// Convert point to string for display
function pointToString(P) {
  if (isInfinity(P)) return 'O (infinity)';
  return `(${P.x}, ${P.y})`;
}

module.exports = {
  EllipticCurve,
  CURVE_SMALL,
  CURVE_TINY,
  CURVE_SECP_LIKE,
  INFINITY,
  isInfinity,
  pointEquals,
  generateKeys,
  ecdhSharedSecret,
  encryptPoint,
  decryptPoint,
  encodeToPoint,
  decodeFromPoint,
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  pointToString
};

// Example usage:
// const ecc = require('./ecc');
// 
// // Use the small educational curve
// const curve = ecc.CURVE_SMALL;
// 
// // Generate key pair
// const keys = ecc.generateKeys(curve);
// console.log('Public Key Q:', ecc.pointToString(keys.publicKey.Q));
// console.log('Private Key d:', keys.privateKey.d);
// 
// // ECDH Key Agreement
// const aliceKeys = ecc.generateKeys(curve);
// const bobKeys = ecc.generateKeys(curve);
// const aliceShared = ecc.ecdhSharedSecret(aliceKeys.privateKey, bobKeys.publicKey, curve);
// const bobShared = ecc.ecdhSharedSecret(bobKeys.privateKey, aliceKeys.publicKey, curve);
// console.log('Alice shared:', ecc.pointToString(aliceShared));
// console.log('Bob shared:', ecc.pointToString(bobShared));
// console.log('Match:', ecc.pointEquals(aliceShared, bobShared));
// 
// // Encrypt/Decrypt a small number
// const message = 5n;
// const encrypted = ecc.encrypt(message, keys.publicKey, curve);
// const decrypted = ecc.decrypt(encrypted, keys.privateKey, curve);
// console.log('Original:', message, 'Decrypted:', decrypted);
