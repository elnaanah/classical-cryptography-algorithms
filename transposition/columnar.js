// Columnar Transposition Cipher
// Write plaintext row-wise, read columns in alphabetical key order

function getColumnOrder(key) {
  // Get column order based on alphabetical sorting of key letters
  const keyUpper = key.toUpperCase();
  const indexed = keyUpper.split('').map((char, i) => ({ char, i }));
  indexed.sort((a, b) => {
    if (a.char !== b.char) return a.char.localeCompare(b.char);
    return a.i - b.i;
  });
  return indexed.map(item => item.i);
}

function encrypt(plaintext, key) {
  if (!key || key.length === 0) throw new Error('Key must not be empty');
  
  const numCols = key.length;
  const order = getColumnOrder(key);
  
  // Build grid row by row
  const grid = [];
  for (let i = 0; i < plaintext.length; i += numCols) {
    grid.push(plaintext.slice(i, i + numCols).split(''));
  }
  
  // Pad last row if needed
  if (grid.length > 0) {
    const lastRow = grid[grid.length - 1];
    while (lastRow.length < numCols) {
      lastRow.push('');
    }
  }
  
  // Read columns in sorted order
  let result = '';
  for (const col of order) {
    for (const row of grid) {
      if (row[col]) result += row[col];
    }
  }
  
  return result;
}

function decrypt(ciphertext, key) {
  if (!key || key.length === 0) throw new Error('Key must not be empty');
  if (ciphertext.length === 0) return '';
  
  const numCols = key.length;
  const numRows = Math.ceil(ciphertext.length / numCols);
  const order = getColumnOrder(key);
  
  // Calculate how many cells are filled in the last row
  const filledInLastRow = ciphertext.length % numCols || numCols;
  
  // Columns that are read FIRST (in sorted order) get full length
  // Columns read LATER (after filledInLastRow) are short
  // order[i] = original column index at sorted position i
  const longColumns = new Set();
  for (let i = 0; i < filledInLastRow; i++) {
    longColumns.add(order[i]); // First 'filledInLastRow' columns in READ ORDER are long
  }
  
  // Split ciphertext into columns based on sorted read order
  const columns = Array.from({ length: numCols }, () => []);
  let index = 0;
  for (let i = 0; i < numCols; i++) {
    const originalCol = order[i];
    const colLength = longColumns.has(originalCol) ? numRows : numRows - 1;
    columns[originalCol] = ciphertext.slice(index, index + colLength).split('');
    index += colLength;
  }
  
  // Read row by row from original column order
  let result = '';
  for (let r = 0; r < numRows; r++) {
    for (let c = 0; c < numCols; c++) {
      if (columns[c][r] !== undefined) {
        result += columns[c][r];
      }
    }
  }
  
  return result;
}

module.exports = { encrypt, decrypt };

// Example usage:
// const columnar = require('./columnar');
// console.log(columnar.encrypt("HELLOWORLD", "ZEBRA"));
// console.log(columnar.decrypt(columnar.encrypt("HELLOWORLD", "ZEBRA"), "ZEBRA"));
