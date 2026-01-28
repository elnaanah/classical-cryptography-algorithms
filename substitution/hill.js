// Hill Cipher
// Encryption: C = K * P mod 26 (matrix multiplication)
// Decryption: P = K⁻¹ * C mod 26
// Key: square matrix (2x2 or 3x3) that is invertible mod 26

const { letterToNum, numToLetter, isLetter, mod, modInverse } = require('../helpers');

function validateKey(key) {
  if (!Array.isArray(key) || key.length === 0) {
    throw new Error('Key must be a non-empty 2D array (square matrix)');
  }
  
  const n = key.length;
  
  for (const row of key) {
    if (!Array.isArray(row) || row.length !== n) {
      throw new Error('Key must be a square matrix (n x n)');
    }
    for (const val of row) {
      if (typeof val !== 'number') {
        throw new Error('Matrix elements must be numbers');
      }
    }
  }
  
  // Check if matrix is invertible mod 26
  const det = determinant(key);
  const detMod = mod(det, 26);
  const detInverse = modInverse(detMod, 26);
  
  if (detInverse === null) {
    throw new Error('Matrix is not invertible mod 26 (determinant must be coprime with 26)');
  }
  
  return key;
}

function determinant(matrix) {
  const n = matrix.length;
  
  if (n === 1) {
    return matrix[0][0];
  }
  
  if (n === 2) {
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  }
  
  // For larger matrices, use cofactor expansion
  let det = 0;
  for (let col = 0; col < n; col++) {
    det += matrix[0][col] * cofactor(matrix, 0, col);
  }
  return det;
}

function cofactor(matrix, row, col) {
  const minor = getMinor(matrix, row, col);
  const sign = ((row + col) % 2 === 0) ? 1 : -1;
  return sign * determinant(minor);
}

function getMinor(matrix, row, col) {
  return matrix
    .filter((_, i) => i !== row)
    .map(r => r.filter((_, j) => j !== col));
}

function matrixInverseMod26(matrix) {
  const n = matrix.length;
  const det = determinant(matrix);
  const detMod = mod(det, 26);
  const detInverse = modInverse(detMod, 26);
  
  // Calculate adjugate matrix (transpose of cofactor matrix)
  const adjugate = [];
  for (let i = 0; i < n; i++) {
    adjugate.push([]);
    for (let j = 0; j < n; j++) {
      // Note: adjugate[i][j] = cofactor[j][i] (transpose)
      adjugate[i].push(mod(cofactor(matrix, j, i) * detInverse, 26));
    }
  }
  
  return adjugate;
}

function multiplyMatrixVector(matrix, vector) {
  const n = matrix.length;
  const result = [];
  
  for (let i = 0; i < n; i++) {
    let sum = 0;
    for (let j = 0; j < n; j++) {
      sum += matrix[i][j] * vector[j];
    }
    result.push(mod(sum, 26));
  }
  
  return result;
}

function encrypt(plaintext, key) {
  const matrix = validateKey(key);
  const n = matrix.length;
  
  // Extract letters and their properties
  const originalChars = plaintext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  
  // Convert to numbers
  let nums = letters.map(c => letterToNum(c));
  
  // Pad with X (23) if necessary
  while (nums.length % n !== 0) {
    nums.push(23); // X
    letterCases.push(true); // Uppercase for padding
  }
  
  // Encrypt in blocks
  const encryptedNums = [];
  for (let i = 0; i < nums.length; i += n) {
    const block = nums.slice(i, i + n);
    const encryptedBlock = multiplyMatrixVector(matrix, block);
    encryptedNums.push(...encryptedBlock);
  }
  
  // Reconstruct with original structure
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;
    } else if (letterIndex < encryptedNums.length) {
      const encrypted = numToLetter(encryptedNums[letterIndex]);
      result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  // Add padding characters
  while (letterIndex < encryptedNums.length) {
    const encrypted = numToLetter(encryptedNums[letterIndex]);
    result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
    letterIndex++;
  }
  
  return result;
}

function decrypt(ciphertext, key) {
  const matrix = validateKey(key);
  const n = matrix.length;
  const inverseMatrix = matrixInverseMod26(matrix);
  
  // Extract letters and their properties
  const originalChars = ciphertext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  
  // Convert to numbers
  let nums = letters.map(c => letterToNum(c));
  
  // Pad if necessary (shouldn't normally happen with proper ciphertext)
  while (nums.length % n !== 0) {
    nums.push(23);
    letterCases.push(true);
  }
  
  // Decrypt in blocks
  const decryptedNums = [];
  for (let i = 0; i < nums.length; i += n) {
    const block = nums.slice(i, i + n);
    const decryptedBlock = multiplyMatrixVector(inverseMatrix, block);
    decryptedNums.push(...decryptedBlock);
  }
  
  // Reconstruct with original structure
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;
    } else if (letterIndex < decryptedNums.length) {
      const decrypted = numToLetter(decryptedNums[letterIndex]);
      result += letterCases[letterIndex] ? decrypted : decrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  return result;
}

module.exports = { encrypt, decrypt };

// Example usage:
// const hill = require('./hill');
// const key2x2 = [[6, 24], [1, 16]]; // Example 2x2 key
// console.log(hill.encrypt("HELP", key2x2));  // DELR (depends on key)
// console.log(hill.decrypt(hill.encrypt("HELP", key2x2), key2x2));  // HELP
