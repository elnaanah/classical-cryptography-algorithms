// Common helper functions for classical cryptography

// Map letter to number (A=0, B=1, ..., Z=25)
function letterToNum(char) {
  return char.toUpperCase().charCodeAt(0) - 65;
}

// Map number to letter (0=A, 1=B, ..., 25=Z)
function numToLetter(num) {
  return String.fromCharCode(((num % 26) + 26) % 26 + 65);
}

// Check if character is a letter
function isLetter(char) {
  return /^[A-Za-z]$/.test(char);
}

// Modulo that handles negative numbers correctly
function mod(n, m) {
  return ((n % m) + m) % m;
}

// Extended Euclidean Algorithm to find modular inverse
function modInverse(a, m) {
  a = mod(a, m);
  for (let x = 1; x < m; x++) {
    if (mod(a * x, m) === 1) return x;
  }
  return null; // No inverse exists
}

// Check if two numbers are coprime
function gcd(a, b) {
  while (b !== 0) {
    [a, b] = [b, a % b];
  }
  return a;
}

function isCoprime(a, b) {
  return gcd(a, b) === 1;
}

module.exports = { letterToNum, numToLetter, isLetter, mod, modInverse, gcd, isCoprime };

