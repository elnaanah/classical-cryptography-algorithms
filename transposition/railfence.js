// Rail Fence Cipher (Transposition)
// Write plaintext diagonally across N rails, read row by row

function encrypt(plaintext, numRails) {
  if (numRails < 2) throw new Error('Number of rails must be at least 2');
  if (plaintext.length === 0) return '';
  
  // Create rails array
  const rails = Array.from({ length: numRails }, () => []);
  let rail = 0;
  let direction = 1; // 1 = down, -1 = up
  
  // Place characters in zig-zag pattern
  for (const char of plaintext) {
    rails[rail].push(char);
    rail += direction;
    // Change direction at top or bottom rail
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  // Read row by row
  return rails.flat().join('');
}

function decrypt(ciphertext, numRails) {
  if (numRails < 2) throw new Error('Number of rails must be at least 2');
  if (ciphertext.length === 0) return '';
  
  const len = ciphertext.length;
  
  // Calculate how many characters go in each rail
  const railLengths = Array(numRails).fill(0);
  let rail = 0;
  let direction = 1;
  
  for (let i = 0; i < len; i++) {
    railLengths[rail]++;
    rail += direction;
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  // Split ciphertext into rails
  const rails = [];
  let index = 0;
  for (let r = 0; r < numRails; r++) {
    rails.push(ciphertext.slice(index, index + railLengths[r]).split(''));
    index += railLengths[r];
  }
  
  // Read in zig-zag order
  const result = [];
  rail = 0;
  direction = 1;
  
  for (let i = 0; i < len; i++) {
    result.push(rails[rail].shift());
    rail += direction;
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  return result.join('');
}

module.exports = { encrypt, decrypt };

// Example usage:
// const railfence = require('./railfence');
// console.log(railfence.encrypt("HELLOWORLD", 3));  // HOLELWRDLO
// console.log(railfence.decrypt("HOLELWRDLO", 3));  // HELLOWORLD

