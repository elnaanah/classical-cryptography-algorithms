/**
 * Classical Cryptography Algorithms - UI Application
 * 
 * This file connects the UI to the cryptographic algorithm implementations.
 * All algorithm logic is adapted from the original Node.js modules for browser use.
 * 
 * Features:
 * - Real-time input validation with educational feedback
 * - Dynamic key input based on selected algorithm
 * - Educational hints explaining each algorithm
 */

// ============================================================================
// HELPER FUNCTIONS (from helpers.js)
// ============================================================================

function letterToNum(char) {
    return char.toUpperCase().charCodeAt(0) - 65;
}

function numToLetter(num) {
    return String.fromCharCode(((num % 26) + 26) % 26 + 65);
}

function isLetter(char) {
    return /^[A-Za-z]$/.test(char);
}

function mod(n, m) {
    return ((n % m) + m) % m;
}

function modInverse(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) {
        if (mod(a * x, m) === 1) return x;
    }
    return null;
}

function gcd(a, b) {
    while (b !== 0) {
        [a, b] = [b, a % b];
    }
    return a;
}

function isCoprime(a, b) {
    return gcd(a, b) === 1;
}

// ============================================================================
// ALGORITHM IMPLEMENTATIONS
// ============================================================================

const algorithms = {
    // -------------------------------------------------------------------------
    // CAESAR CIPHER
    // -------------------------------------------------------------------------
    caesar: {
        name: 'Caesar Cipher',
        formula: 'C = (P + k) mod 26',
        description: 'Shifts each letter by a fixed number of positions in the alphabet.',
        hint: 'The simplest substitution cipher. Julius Caesar used a shift of 3. Try different shift values to see how the alphabet rotates.',
        
        encrypt(plaintext, key) {
            const k = mod(parseInt(key), 26);
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const c = mod(p + k, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const k = mod(parseInt(key), 26);
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const c = letterToNum(char);
                const p = mod(c - k, 26);
                return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // MULTIPLICATIVE CIPHER
    // -------------------------------------------------------------------------
    multiplicative: {
        name: 'Multiplicative Cipher',
        formula: 'C = (P × k) mod 26',
        description: 'Multiplies each letter position by the key. Key must be coprime with 26.',
        hint: 'Only keys coprime with 26 work (no common factors). Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25. Keys like 2, 4, 13 will fail.',
        
        encrypt(plaintext, key) {
            const k = parseInt(key);
            if (!isCoprime(k, 26)) {
                throw new Error(`Key ${k} is not coprime with 26. Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`);
            }
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const c = mod(p * k, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const k = parseInt(key);
            if (!isCoprime(k, 26)) {
                throw new Error(`Key ${k} is not coprime with 26. Valid keys: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25`);
            }
            const kInv = modInverse(k, 26);
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const c = letterToNum(char);
                const p = mod(c * kInv, 26);
                return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // AFFINE CIPHER
    // -------------------------------------------------------------------------
    affine: {
        name: 'Affine Cipher',
        formula: 'C = (a × P + b) mod 26',
        description: 'Combines multiplicative and additive ciphers. Parameter "a" must be coprime with 26.',
        hint: 'Affine = Multiplicative + Caesar combined. "a" handles multiplication (must be coprime with 26), "b" handles addition (shift).',
        
        encrypt(plaintext, key) {
            const { a, b } = key;
            if (!isCoprime(a, 26)) {
                throw new Error('Parameter "a" must be coprime with 26. Valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25');
            }
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const c = mod(a * p + b, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const { a, b } = key;
            if (!isCoprime(a, 26)) {
                throw new Error('Parameter "a" must be coprime with 26. Valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25');
            }
            const aInverse = modInverse(a, 26);
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const c = letterToNum(char);
                const p = mod(aInverse * (c - b), 26);
                return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // MONOALPHABETIC CIPHER
    // -------------------------------------------------------------------------
    monoalphabetic: {
        name: 'Monoalphabetic Cipher',
        formula: 'Fixed alphabet substitution',
        description: 'Each letter maps to exactly one other letter using a 26-letter permutation key.',
        hint: 'Create your own alphabet substitution table. Key must be all 26 letters exactly once. Example: QWERTYUIOPASDFGHJKLZXCVBNM',
        
        ALPHABET: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        
        validateKey(key) {
            const upper = key.toUpperCase();
            if (upper.length !== 26) {
                throw new Error(`Key must be exactly 26 characters (currently ${upper.length})`);
            }
            const sorted = upper.split('').sort().join('');
            if (sorted !== this.ALPHABET) {
                throw new Error('Key must contain each letter A-Z exactly once');
            }
            return upper;
        },
        
        encrypt(plaintext, key) {
            const keyUpper = this.validateKey(key);
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const index = this.ALPHABET.indexOf(char.toUpperCase());
                const encrypted = keyUpper[index];
                return char === char.toUpperCase() ? encrypted : encrypted.toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const keyUpper = this.validateKey(key);
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const index = keyUpper.indexOf(char.toUpperCase());
                const decrypted = this.ALPHABET[index];
                return char === char.toUpperCase() ? decrypted : decrypted.toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // VIGENÈRE CIPHER
    // -------------------------------------------------------------------------
    vigenere: {
        name: 'Vigenère Cipher',
        formula: 'C = (P + K[i]) mod 26',
        description: 'Polyalphabetic cipher using a repeating keyword to shift letters.',
        hint: 'The keyword repeats to match text length. Each letter of the keyword determines the shift for that position. Stronger than Caesar because shift varies.',
        
        encrypt(plaintext, key) {
            const keyUpper = key.toUpperCase().split('').filter(isLetter).join('');
            if (keyUpper.length === 0) throw new Error('Key must contain at least one letter');
            
            let keyIndex = 0;
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
                keyIndex++;
                const c = mod(p + k, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const keyUpper = key.toUpperCase().split('').filter(isLetter).join('');
            if (keyUpper.length === 0) throw new Error('Key must contain at least one letter');
            
            let keyIndex = 0;
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const c = letterToNum(char);
                const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
                keyIndex++;
                const p = mod(c - k, 26);
                return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // AUTOKEY CIPHER
    // -------------------------------------------------------------------------
    autokey: {
        name: 'Autokey Cipher',
        formula: 'Key = keyword + plaintext',
        description: 'Key extends with plaintext letters, making each encryption unique.',
        hint: 'Unlike Vigenère, the key grows by appending plaintext letters. This means the key never repeats, making it harder to crack.',
        
        encrypt(plaintext, key) {
            const initialKey = key.toUpperCase().split('').filter(isLetter).join('');
            if (initialKey.length === 0) throw new Error('Key must contain at least one letter');
            
            const plaintextLetters = plaintext.split('').filter(isLetter).map(c => c.toUpperCase());
            const fullKey = initialKey + plaintextLetters.join('');
            
            let keyIndex = 0;
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const k = letterToNum(fullKey[keyIndex]);
                keyIndex++;
                const c = mod(p + k, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const initialKey = key.toUpperCase().split('').filter(isLetter).join('');
            if (initialKey.length === 0) throw new Error('Key must contain at least one letter');
            
            let keyStream = initialKey.split('');
            let keyIndex = 0;
            
            return ciphertext.split('').map(char => {
                if (!isLetter(char)) return char;
                const c = letterToNum(char);
                const k = letterToNum(keyStream[keyIndex]);
                const p = mod(c - k, 26);
                keyStream.push(numToLetter(p));
                keyIndex++;
                return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
            }).join('');
        }
    },

    // -------------------------------------------------------------------------
    // PLAYFAIR CIPHER
    // -------------------------------------------------------------------------
    playfair: {
        name: 'Playfair Cipher',
        formula: '5×5 matrix digraph cipher',
        description: 'Encrypts pairs of letters using a 5×5 matrix. I and J are treated as one letter.',
        hint: 'Works on letter PAIRS (digraphs). If a pair has same letters, X is inserted between. If odd length, X is added at end. Rules: same row→shift right, same column→shift down, rectangle→swap corners.',
        
        generateMatrix(key) {
            const seen = new Set();
            const keyChars = (key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')
                .toUpperCase()
                .replace(/J/g, 'I')
                .split('')
                .filter(c => {
                    if (!isLetter(c) || seen.has(c)) return false;
                    seen.add(c);
                    return true;
                });
            
            const matrix = [];
            for (let i = 0; i < 5; i++) {
                matrix.push(keyChars.slice(i * 5, i * 5 + 5));
            }
            return matrix;
        },
        
        findPosition(matrix, char) {
            const c = char === 'J' ? 'I' : char;
            for (let row = 0; row < 5; row++) {
                for (let col = 0; col < 5; col++) {
                    if (matrix[row][col] === c) return { row, col };
                }
            }
            return null;
        },
        
        prepareText(text) {
            const letters = text.toUpperCase().split('').filter(isLetter).join('').replace(/J/g, 'I');
            const digraphs = [];
            let i = 0;
            
            while (i < letters.length) {
                const first = letters[i];
                let second;
                
                if (i + 1 >= letters.length) {
                    second = 'X';
                    i++;
                } else if (letters[i] === letters[i + 1]) {
                    second = 'X';
                    i++;
                } else {
                    second = letters[i + 1];
                    i += 2;
                }
                digraphs.push([first, second]);
            }
            return digraphs;
        },
        
        encryptDigraph(matrix, a, b) {
            const posA = this.findPosition(matrix, a);
            const posB = this.findPosition(matrix, b);
            
            if (posA.row === posB.row) {
                return [matrix[posA.row][(posA.col + 1) % 5], matrix[posB.row][(posB.col + 1) % 5]];
            } else if (posA.col === posB.col) {
                return [matrix[(posA.row + 1) % 5][posA.col], matrix[(posB.row + 1) % 5][posB.col]];
            } else {
                return [matrix[posA.row][posB.col], matrix[posB.row][posA.col]];
            }
        },
        
        decryptDigraph(matrix, a, b) {
            const posA = this.findPosition(matrix, a);
            const posB = this.findPosition(matrix, b);
            
            if (posA.row === posB.row) {
                return [matrix[posA.row][(posA.col + 4) % 5], matrix[posB.row][(posB.col + 4) % 5]];
            } else if (posA.col === posB.col) {
                return [matrix[(posA.row + 4) % 5][posA.col], matrix[(posB.row + 4) % 5][posB.col]];
            } else {
                return [matrix[posA.row][posB.col], matrix[posB.row][posA.col]];
            }
        },
        
        encrypt(plaintext, key) {
            if (!key || key.length === 0) throw new Error('Key must not be empty');
            
            const matrix = this.generateMatrix(key);
            const digraphs = this.prepareText(plaintext);
            const originalChars = plaintext.split('');
            const letterCases = originalChars.filter(isLetter).map(c => c === c.toUpperCase());
            
            const encryptedLetters = digraphs.map(([a, b]) => this.encryptDigraph(matrix, a, b)).flat();
            
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
            
            while (letterIndex < encryptedLetters.length) {
                result += encryptedLetters[letterIndex];
                letterIndex++;
            }
            
            return result;
        },
        
        decrypt(ciphertext, key) {
            if (!key || key.length === 0) throw new Error('Key must not be empty');
            
            const matrix = this.generateMatrix(key);
            const originalChars = ciphertext.split('');
            const letters = originalChars.filter(isLetter);
            const letterCases = letters.map(c => c === c.toUpperCase());
            const upperLetters = letters.map(c => c.toUpperCase().replace(/J/g, 'I')).join('');
            
            const digraphs = [];
            for (let i = 0; i < upperLetters.length; i += 2) {
                if (i + 1 < upperLetters.length) {
                    digraphs.push([upperLetters[i], upperLetters[i + 1]]);
                } else {
                    digraphs.push([upperLetters[i], 'X']);
                }
            }
            
            const decryptedLetters = digraphs.map(([a, b]) => this.decryptDigraph(matrix, a, b)).flat().slice(0, letters.length);
            
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
    },

    // -------------------------------------------------------------------------
    // HILL CIPHER
    // -------------------------------------------------------------------------
    hill: {
        name: 'Hill Cipher',
        formula: 'C = K × P mod 26',
        description: 'Uses matrix multiplication for encryption. Matrix must be invertible mod 26.',
        hint: 'Text is converted to number vectors and multiplied by key matrix. For decryption, we need the inverse matrix. Determinant must be coprime with 26 (not 0, 2, 4, 6, 8, 10, 12, 13, 14...).',
        
        determinant(matrix) {
            const n = matrix.length;
            if (n === 1) return matrix[0][0];
            if (n === 2) return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
            
            let det = 0;
            for (let col = 0; col < n; col++) {
                det += matrix[0][col] * this.cofactor(matrix, 0, col);
            }
            return det;
        },
        
        cofactor(matrix, row, col) {
            const minor = this.getMinor(matrix, row, col);
            const sign = ((row + col) % 2 === 0) ? 1 : -1;
            return sign * this.determinant(minor);
        },
        
        getMinor(matrix, row, col) {
            return matrix.filter((_, i) => i !== row).map(r => r.filter((_, j) => j !== col));
        },
        
        matrixInverseMod26(matrix) {
            const n = matrix.length;
            const det = this.determinant(matrix);
            const detMod = mod(det, 26);
            const detInverse = modInverse(detMod, 26);
            
            if (detInverse === null) {
                throw new Error('Matrix is not invertible mod 26 (determinant must be coprime with 26)');
            }
            
            const adjugate = [];
            for (let i = 0; i < n; i++) {
                adjugate.push([]);
                for (let j = 0; j < n; j++) {
                    adjugate[i].push(mod(this.cofactor(matrix, j, i) * detInverse, 26));
                }
            }
            return adjugate;
        },
        
        multiplyMatrixVector(matrix, vector) {
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
        },
        
        validateKey(key) {
            const n = key.length;
            for (const row of key) {
                if (row.length !== n) throw new Error('Key must be a square matrix');
            }
            
            const det = this.determinant(key);
            const detMod = mod(det, 26);
            if (modInverse(detMod, 26) === null) {
                throw new Error(`Matrix determinant (${detMod}) is not coprime with 26. Matrix cannot be inverted.`);
            }
            return key;
        },
        
        encrypt(plaintext, key) {
            const matrix = this.validateKey(key);
            const n = matrix.length;
            
            const originalChars = plaintext.split('');
            const letters = originalChars.filter(isLetter);
            const letterCases = letters.map(c => c === c.toUpperCase());
            
            let nums = letters.map(c => letterToNum(c));
            while (nums.length % n !== 0) {
                nums.push(23); // X
                letterCases.push(true);
            }
            
            const encryptedNums = [];
            for (let i = 0; i < nums.length; i += n) {
                const block = nums.slice(i, i + n);
                encryptedNums.push(...this.multiplyMatrixVector(matrix, block));
            }
            
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
            
            while (letterIndex < encryptedNums.length) {
                const encrypted = numToLetter(encryptedNums[letterIndex]);
                result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
                letterIndex++;
            }
            
            return result;
        },
        
        decrypt(ciphertext, key) {
            const matrix = this.validateKey(key);
            const n = matrix.length;
            const inverseMatrix = this.matrixInverseMod26(matrix);
            
            const originalChars = ciphertext.split('');
            const letters = originalChars.filter(isLetter);
            const letterCases = letters.map(c => c === c.toUpperCase());
            
            let nums = letters.map(c => letterToNum(c));
            while (nums.length % n !== 0) {
                nums.push(23);
                letterCases.push(true);
            }
            
            const decryptedNums = [];
            for (let i = 0; i < nums.length; i += n) {
                const block = nums.slice(i, i + n);
                decryptedNums.push(...this.multiplyMatrixVector(inverseMatrix, block));
            }
            
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
    },

    // -------------------------------------------------------------------------
    // ONE-TIME PAD
    // -------------------------------------------------------------------------
    otp: {
        name: 'One-Time Pad',
        formula: 'C = (P + K) mod 26',
        description: 'Perfectly secure when key is random and same length as message.',
        hint: 'The ONLY theoretically unbreakable cipher IF: (1) key is truly random, (2) key length equals message length, (3) key is NEVER reused. Breaking any rule destroys security.',
        
        validateKey(text, key) {
            const textLetterCount = text.split('').filter(isLetter).length;
            const keyLetters = key.split('').filter(isLetter);
            
            if (keyLetters.length !== textLetterCount) {
                throw new Error(`Key has ${keyLetters.length} letters but text has ${textLetterCount} letters. They must match exactly.`);
            }
            return keyLetters.map(c => c.toUpperCase()).join('');
        },
        
        encrypt(plaintext, key) {
            const keyUpper = this.validateKey(plaintext, key);
            let keyIndex = 0;
            
            return plaintext.split('').map(char => {
                if (!isLetter(char)) return char;
                const p = letterToNum(char);
                const k = letterToNum(keyUpper[keyIndex]);
                keyIndex++;
                const c = mod(p + k, 26);
                return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
            }).join('');
        },
        
        decrypt(ciphertext, key) {
            const keyUpper = this.validateKey(ciphertext, key);
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
    },

    // -------------------------------------------------------------------------
    // RAIL FENCE CIPHER
    // -------------------------------------------------------------------------
    railfence: {
        name: 'Rail Fence Cipher',
        formula: 'Zigzag transposition',
        description: 'Writes text in zigzag pattern across rails, then reads row by row.',
        hint: 'A transposition cipher (letters stay same, positions change). Text is written diagonally across N rows, then read horizontally. More rails = more scrambling.',
        
        encrypt(plaintext, numRails) {
            const n = parseInt(numRails);
            if (n < 2) throw new Error('Number of rails must be at least 2');
            if (plaintext.length === 0) return '';
            
            const rails = Array.from({ length: n }, () => []);
            let rail = 0;
            let direction = 1;
            
            for (const char of plaintext) {
                rails[rail].push(char);
                rail += direction;
                if (rail === 0 || rail === n - 1) direction = -direction;
            }
            
            return rails.flat().join('');
        },
        
        decrypt(ciphertext, numRails) {
            const n = parseInt(numRails);
            if (n < 2) throw new Error('Number of rails must be at least 2');
            if (ciphertext.length === 0) return '';
            
            const len = ciphertext.length;
            const railLengths = Array(n).fill(0);
            let rail = 0;
            let direction = 1;
            
            for (let i = 0; i < len; i++) {
                railLengths[rail]++;
                rail += direction;
                if (rail === 0 || rail === n - 1) direction = -direction;
            }
            
            const rails = [];
            let index = 0;
            for (let r = 0; r < n; r++) {
                rails.push(ciphertext.slice(index, index + railLengths[r]).split(''));
                index += railLengths[r];
            }
            
            const result = [];
            rail = 0;
            direction = 1;
            
            for (let i = 0; i < len; i++) {
                result.push(rails[rail].shift());
                rail += direction;
                if (rail === 0 || rail === n - 1) direction = -direction;
            }
            
            return result.join('');
        }
    },

    // -------------------------------------------------------------------------
    // COLUMNAR TRANSPOSITION
    // -------------------------------------------------------------------------
    columnar: {
        name: 'Columnar Transposition',
        formula: 'Row-wise write, column-wise read',
        description: 'Arranges text in columns, reads in alphabetical order of keyword letters.',
        hint: 'Text fills a grid row by row. Columns are read in the alphabetical order of the keyword. Example: keyword "ZEBRA" gives column order 5,2,1,4,3.',
        
        getColumnOrder(key) {
            const keyUpper = key.toUpperCase();
            const indexed = keyUpper.split('').map((char, i) => ({ char, i }));
            indexed.sort((a, b) => {
                if (a.char !== b.char) return a.char.localeCompare(b.char);
                return a.i - b.i;
            });
            return indexed.map(item => item.i);
        },
        
        encrypt(plaintext, key) {
            if (!key || key.length === 0) throw new Error('Key must not be empty');
            
            const numCols = key.length;
            const order = this.getColumnOrder(key);
            
            const grid = [];
            for (let i = 0; i < plaintext.length; i += numCols) {
                grid.push(plaintext.slice(i, i + numCols).split(''));
            }
            
            if (grid.length > 0) {
                const lastRow = grid[grid.length - 1];
                while (lastRow.length < numCols) {
                    lastRow.push('');
                }
            }
            
            let result = '';
            for (const col of order) {
                for (const row of grid) {
                    if (row[col]) result += row[col];
                }
            }
            
            return result;
        },
        
        decrypt(ciphertext, key) {
            if (!key || key.length === 0) throw new Error('Key must not be empty');
            if (ciphertext.length === 0) return '';
            
            const numCols = key.length;
            const numRows = Math.ceil(ciphertext.length / numCols);
            const order = this.getColumnOrder(key);
            
            const filledInLastRow = ciphertext.length % numCols || numCols;
            
            const longColumns = new Set();
            for (let i = 0; i < filledInLastRow; i++) {
                longColumns.add(order[i]);
            }
            
            const columns = Array.from({ length: numCols }, () => []);
            let index = 0;
            for (let i = 0; i < numCols; i++) {
                const originalCol = order[i];
                const colLength = longColumns.has(originalCol) ? numRows : numRows - 1;
                columns[originalCol] = ciphertext.slice(index, index + colLength).split('');
                index += colLength;
            }
            
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
    }
};

// ============================================================================
// VALIDATION ENGINE
// ============================================================================

const Validator = {
    // Validate key based on algorithm type
    validate(algo, key, text) {
        const textLetterCount = text.split('').filter(isLetter).length;
        
        switch (algo) {
            case 'caesar':
                const caesarKey = parseInt(key);
                if (isNaN(caesarKey)) return { valid: false, message: 'Enter a number for the shift value' };
                return { valid: true, message: `Shift: ${mod(caesarKey, 26)} positions` };
                
            case 'multiplicative':
                const multKey = parseInt(key);
                if (isNaN(multKey)) return { valid: false, message: 'Enter a number for the key' };
                if (!isCoprime(multKey, 26)) return { valid: false, message: `${multKey} is NOT coprime with 26. Use: 1,3,5,7,9,11,15,17,19,21,23,25` };
                return { valid: true, message: `Key ${multKey} is valid (coprime with 26)` };
                
            case 'affine':
                const a = parseInt(key.a);
                const b = parseInt(key.b);
                if (isNaN(a) || isNaN(b)) return { valid: false, message: 'Enter numbers for both a and b' };
                if (!isCoprime(a, 26)) return { valid: false, message: `a=${a} is NOT coprime with 26. Valid: 1,3,5,7,9,11,15,17,19,21,23,25` };
                return { valid: true, message: `a=${a} (valid), b=${b}` };
                
            case 'monoalphabetic':
                const monoKey = (key || '').toUpperCase();
                const uniqueLetters = new Set(monoKey.split('').filter(isLetter));
                if (monoKey.length < 26) return { valid: false, message: `Need 26 letters, have ${monoKey.length}` };
                if (uniqueLetters.size !== 26) return { valid: false, message: 'Key must contain each letter A-Z exactly once' };
                return { valid: true, message: 'Valid 26-letter permutation' };
                
            case 'vigenere':
            case 'autokey':
            case 'playfair':
            case 'columnar':
                const textKey = (key || '').trim();
                if (!textKey) return { valid: false, message: 'Enter a keyword' };
                const keyLetters = textKey.split('').filter(isLetter);
                if (keyLetters.length === 0) return { valid: false, message: 'Keyword must contain at least one letter' };
                return { valid: true, message: `Keyword: "${keyLetters.join('').toUpperCase()}" (${keyLetters.length} letters)` };
                
            case 'otp':
                const otpKey = (key || '').split('').filter(isLetter);
                if (otpKey.length === 0) return { valid: false, message: 'Enter a key' };
                if (otpKey.length !== textLetterCount) {
                    return { valid: false, message: `Key: ${otpKey.length} letters, Text: ${textLetterCount} letters (must match!)` };
                }
                return { valid: true, message: `Key and text both have ${textLetterCount} letters` };
                
            case 'railfence':
                const rails = parseInt(key);
                if (isNaN(rails)) return { valid: false, message: 'Enter the number of rails' };
                if (rails < 2) return { valid: false, message: 'Rails must be at least 2' };
                return { valid: true, message: `${rails} rails` };
                
            case 'hill':
                if (!key || !Array.isArray(key)) return { valid: false, message: 'Fill in the matrix' };
                const n = key.length;
                let hasEmpty = false;
                for (const row of key) {
                    for (const val of row) {
                        if (val === '' || val === undefined || isNaN(val)) hasEmpty = true;
                    }
                }
                if (hasEmpty) return { valid: false, message: 'Fill in all matrix cells' };
                
                const det = algorithms.hill.determinant(key);
                const detMod = mod(det, 26);
                if (modInverse(detMod, 26) === null) {
                    return { valid: false, message: `Determinant ${detMod} is not coprime with 26 (not invertible)` };
                }
                return { valid: true, message: `Determinant: ${detMod} (invertible mod 26)` };
                
            default:
                return { valid: false, message: 'Unknown algorithm' };
        }
    }
};

// ============================================================================
// UI CONTROLLER
// ============================================================================

const UI = {
    elements: {},
    
    init() {
        this.cacheElements();
        this.bindEvents();
        this.updateAlgorithmUI();
        this.updateCharCount();
    },
    
    cacheElements() {
        this.elements = {
            algorithmSelect: document.getElementById('algorithm-select'),
            algoName: document.getElementById('algo-name'),
            algoFormula: document.getElementById('algo-formula'),
            algoDesc: document.getElementById('algo-desc'),
            eduHintText: document.getElementById('edu-hint-text'),
            inputText: document.getElementById('input-text'),
            outputText: document.getElementById('output-text'),
            btnEncrypt: document.getElementById('btn-encrypt'),
            btnDecrypt: document.getElementById('btn-decrypt'),
            btnCopy: document.getElementById('btn-copy'),
            btnSwap: document.getElementById('btn-swap'),
            errorMessage: document.getElementById('error-message'),
            letterCount: document.getElementById('letter-count'),
            totalCount: document.getElementById('total-count'),
            
            // Validation
            validationStatus: document.getElementById('validation-status'),
            statusIcon: document.getElementById('status-icon'),
            statusText: document.getElementById('status-text'),
            
            // Key inputs
            keyNumber: document.getElementById('key-number'),
            keyNum: document.getElementById('key-num'),
            keyHint: document.getElementById('key-hint'),
            
            keyAffine: document.getElementById('key-affine'),
            keyA: document.getElementById('key-a'),
            keyB: document.getElementById('key-b'),
            
            keyText: document.getElementById('key-text'),
            keyWord: document.getElementById('key-word'),
            keyTextHint: document.getElementById('key-text-hint'),
            
            keyOtp: document.getElementById('key-otp'),
            keyOtpText: document.getElementById('key-otp-text'),
            otpTextLen: document.getElementById('otp-text-len'),
            otpKeyLen: document.getElementById('otp-key-len'),
            otpMatch: document.getElementById('otp-match'),
            
            keyMono: document.getElementById('key-mono'),
            keyMonoText: document.getElementById('key-mono-text'),
            monoCount: document.getElementById('mono-count'),
            
            keyHill: document.getElementById('key-hill'),
            hillSize: document.getElementById('hill-size'),
            hillMatrix2: document.getElementById('hill-matrix-2'),
            hillMatrix3: document.getElementById('hill-matrix-3'),
            hillDet: document.getElementById('hill-det')
        };
    },
    
    // Algorithm to key type mapping
    keyTypes: {
        caesar: 'number',
        multiplicative: 'number',
        affine: 'affine',
        monoalphabetic: 'mono',
        vigenere: 'text',
        autokey: 'text',
        playfair: 'text',
        hill: 'hill',
        otp: 'otp',
        railfence: 'number',
        columnar: 'text'
    },
    
    // Key hints
    keyHints: {
        caesar: 'Shift value (0-25)',
        multiplicative: 'Must be coprime with 26',
        railfence: 'Number of rails (minimum 2)',
        vigenere: 'Keyword (letters only, will repeat)',
        autokey: 'Initial keyword (plaintext extends key)',
        playfair: 'Keyword for building 5×5 matrix',
        columnar: 'Keyword determines column read order'
    },
    
    bindEvents() {
        // Algorithm change
        this.elements.algorithmSelect.addEventListener('change', () => {
            this.updateAlgorithmUI();
            this.validateAndUpdate();
        });
        
        // Process buttons
        this.elements.btnEncrypt.addEventListener('click', () => this.process('encrypt'));
        this.elements.btnDecrypt.addEventListener('click', () => this.process('decrypt'));
        this.elements.btnCopy.addEventListener('click', () => this.copyOutput());
        this.elements.btnSwap.addEventListener('click', () => this.swapOutput());
        
        // Input text changes
        this.elements.inputText.addEventListener('input', () => {
            this.updateCharCount();
            this.validateAndUpdate();
        });
        
        // Key input changes - add listeners for real-time validation
        this.elements.keyNum.addEventListener('input', () => this.validateAndUpdate());
        this.elements.keyA.addEventListener('input', () => this.validateAndUpdate());
        this.elements.keyB.addEventListener('input', () => this.validateAndUpdate());
        this.elements.keyWord.addEventListener('input', () => this.validateAndUpdate());
        this.elements.keyOtpText.addEventListener('input', () => {
            this.updateOtpCounter();
            this.validateAndUpdate();
        });
        this.elements.keyMonoText.addEventListener('input', () => {
            this.updateMonoCounter();
            this.validateAndUpdate();
        });
        
        // Hill matrix
        this.elements.hillSize.addEventListener('change', () => {
            this.updateHillMatrix();
            this.validateAndUpdate();
        });
        
        // Hill matrix cells
        document.querySelectorAll('.matrix-cell').forEach(cell => {
            cell.addEventListener('input', () => {
                this.updateHillDeterminant();
                this.validateAndUpdate();
            });
        });
    },
    
    updateAlgorithmUI() {
        const algo = this.elements.algorithmSelect.value;
        const algoData = algorithms[algo];
        
        // Update info card
        this.elements.algoName.textContent = algoData.name;
        this.elements.algoFormula.textContent = algoData.formula;
        this.elements.algoDesc.textContent = algoData.description;
        this.elements.eduHintText.textContent = algoData.hint;
        
        // Hide all key inputs
        this.elements.keyNumber.classList.add('hidden');
        this.elements.keyAffine.classList.add('hidden');
        this.elements.keyText.classList.add('hidden');
        this.elements.keyOtp.classList.add('hidden');
        this.elements.keyMono.classList.add('hidden');
        this.elements.keyHill.classList.add('hidden');
        
        // Show appropriate key input
        const keyType = this.keyTypes[algo];
        
        switch (keyType) {
            case 'number':
                this.elements.keyNumber.classList.remove('hidden');
                this.elements.keyHint.textContent = this.keyHints[algo] || '';
                break;
            case 'affine':
                this.elements.keyAffine.classList.remove('hidden');
                break;
            case 'text':
                this.elements.keyText.classList.remove('hidden');
                this.elements.keyTextHint.textContent = this.keyHints[algo] || '';
                break;
            case 'otp':
                this.elements.keyOtp.classList.remove('hidden');
                this.updateOtpCounter();
                break;
            case 'mono':
                this.elements.keyMono.classList.remove('hidden');
                this.updateMonoCounter();
                break;
            case 'hill':
                this.elements.keyHill.classList.remove('hidden');
                this.updateHillMatrix();
                this.updateHillDeterminant();
                break;
        }
        
        this.hideError();
    },
    
    updateHillMatrix() {
        const size = this.elements.hillSize.value;
        if (size === '2') {
            this.elements.hillMatrix2.classList.remove('hidden');
            this.elements.hillMatrix3.classList.add('hidden');
        } else {
            this.elements.hillMatrix2.classList.add('hidden');
            this.elements.hillMatrix3.classList.remove('hidden');
        }
        this.updateHillDeterminant();
    },
    
    updateHillDeterminant() {
        const matrix = this.getHillMatrix();
        let hasEmpty = false;
        for (const row of matrix) {
            for (const val of row) {
                if (val === '' || val === undefined || isNaN(val)) hasEmpty = true;
            }
        }
        
        if (hasEmpty) {
            this.elements.hillDet.innerHTML = 'Determinant: <strong>—</strong>';
            this.elements.hillDet.className = 'hill-det';
            return;
        }
        
        const det = algorithms.hill.determinant(matrix);
        const detMod = mod(det, 26);
        const isValid = modInverse(detMod, 26) !== null;
        
        this.elements.hillDet.innerHTML = `Determinant: <strong>${detMod}</strong> ${isValid ? '(invertible)' : '(NOT invertible)'}`;
        this.elements.hillDet.className = `hill-det ${isValid ? 'valid' : 'invalid'}`;
    },
    
    updateCharCount() {
        const text = this.elements.inputText.value;
        const letters = text.split('').filter(isLetter).length;
        this.elements.letterCount.textContent = letters;
        this.elements.totalCount.textContent = text.length;
    },
    
    updateOtpCounter() {
        const textLetters = this.elements.inputText.value.split('').filter(isLetter).length;
        const keyLetters = this.elements.keyOtpText.value.split('').filter(isLetter).length;
        
        this.elements.otpTextLen.textContent = textLetters;
        this.elements.otpKeyLen.textContent = keyLetters;
        
        if (keyLetters === textLetters && textLetters > 0) {
            this.elements.otpMatch.textContent = '✓ Match';
            this.elements.otpMatch.className = 'otp-match otp-matched';
        } else {
            this.elements.otpMatch.textContent = '✗ Mismatch';
            this.elements.otpMatch.className = 'otp-match otp-mismatch';
        }
    },
    
    updateMonoCounter() {
        const keyText = this.elements.keyMonoText.value.toUpperCase();
        const letters = keyText.split('').filter(isLetter);
        this.elements.monoCount.textContent = letters.length;
    },
    
    getKey() {
        const algo = this.elements.algorithmSelect.value;
        const keyType = this.keyTypes[algo];
        
        switch (keyType) {
            case 'number':
                return parseInt(this.elements.keyNum.value);
                
            case 'affine':
                return {
                    a: parseInt(this.elements.keyA.value),
                    b: parseInt(this.elements.keyB.value)
                };
                
            case 'text':
                return this.elements.keyWord.value.trim();
                
            case 'otp':
                return this.elements.keyOtpText.value;
                
            case 'mono':
                return this.elements.keyMonoText.value;
                
            case 'hill':
                return this.getHillMatrix();
                
            default:
                return null;
        }
    },
    
    getHillMatrix() {
        const size = parseInt(this.elements.hillSize.value);
        const container = size === 2 ? this.elements.hillMatrix2 : this.elements.hillMatrix3;
        const cells = container.querySelectorAll('.matrix-cell');
        
        const matrix = [];
        for (let i = 0; i < size; i++) {
            matrix.push([]);
            for (let j = 0; j < size; j++) {
                const value = parseInt(cells[i * size + j].value);
                matrix[i].push(isNaN(value) ? '' : value);
            }
        }
        
        return matrix;
    },
    
    validateAndUpdate() {
        const algo = this.elements.algorithmSelect.value;
        const key = this.getKey();
        const text = this.elements.inputText.value;
        
        const result = Validator.validate(algo, key, text);
        
        // Update validation status display
        this.elements.statusIcon.textContent = result.valid ? '✓' : '○';
        this.elements.statusText.textContent = result.message;
        
        this.elements.validationStatus.classList.remove('valid', 'invalid', 'pending');
        if (result.valid) {
            this.elements.validationStatus.classList.add('valid');
        } else if (result.message.includes('Enter') || result.message.includes('Fill')) {
            this.elements.validationStatus.classList.add('pending');
        } else {
            this.elements.validationStatus.classList.add('invalid');
        }
        
        // Enable/disable buttons
        const canProcess = result.valid && text.trim().length > 0;
        this.elements.btnEncrypt.disabled = !canProcess;
        this.elements.btnDecrypt.disabled = !canProcess;
    },
    
    process(operation) {
        try {
            this.hideError();
            
            const algo = this.elements.algorithmSelect.value;
            const text = this.elements.inputText.value;
            const key = this.getKey();
            
            if (!text) {
                throw new Error('Please enter some text');
            }
            
            const algorithm = algorithms[algo];
            const result = operation === 'encrypt' 
                ? algorithm.encrypt(text, key)
                : algorithm.decrypt(text, key);
            
            this.elements.outputText.value = result;
            
        } catch (error) {
            this.showError(error.message);
        }
    },
    
    copyOutput() {
        const output = this.elements.outputText.value;
        if (!output) return;
        
        navigator.clipboard.writeText(output).then(() => {
            const btn = this.elements.btnCopy;
            const originalText = btn.textContent;
            btn.textContent = '✓ Copied!';
            setTimeout(() => btn.textContent = originalText, 1500);
        });
    },
    
    swapOutput() {
        const output = this.elements.outputText.value;
        if (!output) return;
        
        this.elements.inputText.value = output;
        this.elements.outputText.value = '';
        this.updateCharCount();
        this.validateAndUpdate();
    },
    
    showError(message) {
        this.elements.errorMessage.textContent = '⚠ ' + message;
        this.elements.errorMessage.classList.remove('hidden');
    },
    
    hideError() {
        this.elements.errorMessage.classList.add('hidden');
    }
};

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => UI.init());
