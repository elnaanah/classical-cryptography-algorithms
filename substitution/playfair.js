// Playfair Cipher
// Uses a 5x5 matrix built from a keyword
// I and J are treated as the same letter
// Encrypts digraphs (pairs of letters)

const { isLetter } = require('../helpers');

function generateMatrix(key) {
  const seen = new Set();
  const matrix = [];
  
  // Normalize key: uppercase, replace J with I, remove duplicates
  const keyChars = (key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')
    .toUpperCase()
    .replace(/J/g, 'I')
    .split('')
    .filter(c => {
      if (!isLetter(c) || seen.has(c)) return false;
      seen.add(c);
      return true;
    });
  
  // Build 5x5 matrix
  for (let i = 0; i < 5; i++) {
    matrix.push(keyChars.slice(i * 5, i * 5 + 5));
  }
  
  return matrix;
}

function findPosition(matrix, char) {
  const c = char === 'J' ? 'I' : char;
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 5; col++) {
      if (matrix[row][col] === c) {
        return { row, col };
      }
    }
  }
  return null;
}

function prepareText(text) {
  // Extract only letters, uppercase, replace J with I
  const letters = text.toUpperCase().split('').filter(isLetter).join('').replace(/J/g, 'I');
  
  // Create digraphs, inserting X between repeated letters
  const digraphs = [];
  let i = 0;
  
  while (i < letters.length) {
    const first = letters[i];
    let second;
    
    if (i + 1 >= letters.length) {
      // Odd length: add X as padding
      second = 'X';
      i++;
    } else if (letters[i] === letters[i + 1]) {
      // Same letters: insert X
      second = 'X';
      i++;
    } else {
      second = letters[i + 1];
      i += 2;
    }
    
    digraphs.push([first, second]);
  }
  
  return digraphs;
}

function encryptDigraph(matrix, a, b) {
  const posA = findPosition(matrix, a);
  const posB = findPosition(matrix, b);
  
  if (posA.row === posB.row) {
    // Same row: shift right
    return [
      matrix[posA.row][(posA.col + 1) % 5],
      matrix[posB.row][(posB.col + 1) % 5]
    ];
  } else if (posA.col === posB.col) {
    // Same column: shift down
    return [
      matrix[(posA.row + 1) % 5][posA.col],
      matrix[(posB.row + 1) % 5][posB.col]
    ];
  } else {
    // Rectangle: swap columns
    return [
      matrix[posA.row][posB.col],
      matrix[posB.row][posA.col]
    ];
  }
}

function decryptDigraph(matrix, a, b) {
  const posA = findPosition(matrix, a);
  const posB = findPosition(matrix, b);
  
  if (posA.row === posB.row) {
    // Same row: shift left
    return [
      matrix[posA.row][(posA.col + 4) % 5],
      matrix[posB.row][(posB.col + 4) % 5]
    ];
  } else if (posA.col === posB.col) {
    // Same column: shift up
    return [
      matrix[(posA.row + 4) % 5][posA.col],
      matrix[(posB.row + 4) % 5][posB.col]
    ];
  } else {
    // Rectangle: swap columns
    return [
      matrix[posA.row][posB.col],
      matrix[posB.row][posA.col]
    ];
  }
}

function encrypt(plaintext, key) {
  const matrix = generateMatrix(key);
  const digraphs = prepareText(plaintext);
  
  // Track original case and non-letter positions
  const originalChars = plaintext.split('');
  const letterCases = originalChars.filter(isLetter).map(c => c === c.toUpperCase());
  
  // Encrypt digraphs
  const encryptedLetters = digraphs
    .map(([a, b]) => encryptDigraph(matrix, a, b))
    .flat();
  
  // Reconstruct with original structure (preserve non-letters and case)
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;
    } else if (letterIndex < encryptedLetters.length) {
      const encrypted = encryptedLetters[letterIndex];
      result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  // Add any extra characters (from padding)
  while (letterIndex < encryptedLetters.length) {
    result += encryptedLetters[letterIndex];
    letterIndex++;
  }
  
  return result;
}

function decrypt(ciphertext, key) {
  const matrix = generateMatrix(key);
  
  // Extract letters and their cases
  const originalChars = ciphertext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  const upperLetters = letters.map(c => c.toUpperCase().replace(/J/g, 'I')).join('');
  
  // Create digraphs from ciphertext
  const digraphs = [];
  for (let i = 0; i < upperLetters.length; i += 2) {
    if (i + 1 < upperLetters.length) {
      digraphs.push([upperLetters[i], upperLetters[i + 1]]);
    } else {
      digraphs.push([upperLetters[i], 'X']);
    }
  }
  
  // Decrypt digraphs
  const decryptedLetters = digraphs
    .map(([a, b]) => decryptDigraph(matrix, a, b))
    .flat()
    .slice(0, letters.length);
  
  // Reconstruct with original structure
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;
    } else if (letterIndex < decryptedLetters.length) {
      const decrypted = decryptedLetters[letterIndex];
      result += letterCases[letterIndex] ? decrypted : decrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  return result;
}

module.exports = { encrypt, decrypt };

// Example usage:
// const playfair = require('./playfair');
// console.log(playfair.encrypt("HELLO", "MONARCHY"));  // CFSUPM
// console.log(playfair.decrypt("CFSUPM", "MONARCHY"));  // HELXLO
