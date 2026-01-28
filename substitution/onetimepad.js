// One-Time Pad (Vernam Cipher)
// Key must be exactly as long as the plaintext
// Encryption: C = (P + K) mod 26
// Decryption: P = (C - K) mod 26
// Provides perfect secrecy when key is truly random and never reused

const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

function validateKey(text, key) {
  // Count letters in text
  const textLetterCount = text.split('').filter(isLetter).length;
  
  // Extract letters from key
  const keyLetters = key.split('').filter(isLetter);
  
  if (keyLetters.length !== textLetterCount) {
    throw new Error(
      `Key length (${keyLetters.length} letters) must equal text length (${textLetterCount} letters). ` +
      'One-Time Pad requires the key to be exactly as long as the message.'
    );
  }
  
  return keyLetters.map(c => c.toUpperCase()).join('');
}

function encrypt(plaintext, key) {
  const keyUpper = validateKey(plaintext, key);
  let keyIndex = 0;
  
  return plaintext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const p = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex]);
    keyIndex++;
    
    const c = mod(p + k, 26);
    
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

function decrypt(ciphertext, key) {
  const keyUpper = validateKey(ciphertext, key);
  let keyIndex = 0;
  
  return ciphertext.split('').map(char => {
    if (!isLetter(char)) return char;
    
    const c = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex]);
    keyIndex++;
    
    const p = mod(c - k, 26);
    
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const otp = require('./onetimepad');
// console.log(otp.encrypt("HELLO", "XMCKL"));  // EQNVZ
// console.log(otp.decrypt("EQNVZ", "XMCKL"));  // HELLO
