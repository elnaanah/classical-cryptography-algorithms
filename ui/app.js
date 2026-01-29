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

// ============================================================================
// ALGORITHM CLASSIFICATION (Educational)
// ============================================================================

const algorithmClassification = {
    caesar: { type: 'Substitution', subtype: 'Monoalphabetic', security: '⭐ Weak', securityLevel: 1 },
    multiplicative: { type: 'Substitution', subtype: 'Monoalphabetic', security: '⭐ Weak', securityLevel: 1 },
    affine: { type: 'Substitution', subtype: 'Monoalphabetic', security: '⭐⭐ Weak', securityLevel: 2 },
    monoalphabetic: { type: 'Substitution', subtype: 'Monoalphabetic', security: '⭐⭐ Weak', securityLevel: 2 },
    vigenere: { type: 'Substitution', subtype: 'Polyalphabetic', security: '⭐⭐ Medium', securityLevel: 2 },
    autokey: { type: 'Substitution', subtype: 'Polyalphabetic', security: '⭐⭐⭐ Medium+', securityLevel: 3 },
    otp: { type: 'Substitution', subtype: 'Polyalphabetic', security: '⭐⭐⭐⭐⭐ Perfect*', securityLevel: 5 },
    playfair: { type: 'Substitution', subtype: 'Polygraphic (Block)', security: '⭐⭐⭐ Medium', securityLevel: 3 },
    hill: { type: 'Substitution', subtype: 'Polygraphic (Block)', security: '⭐⭐⭐ Medium+', securityLevel: 3 },
    railfence: { type: 'Transposition', subtype: 'Geometric', security: '⭐⭐ Weak', securityLevel: 2 },
    columnar: { type: 'Transposition', subtype: 'Columnar', security: '⭐⭐⭐ Medium', securityLevel: 3 },
    des: { type: 'Modern Symmetric', subtype: 'Block Cipher (Feistel)', security: '⭐⭐⭐ Legacy', securityLevel: 3, isModern: true },
    aes: { type: 'Modern Symmetric', subtype: 'Block Cipher (SPN)', security: '⭐⭐⭐⭐⭐ Strong', securityLevel: 5, isModern: true },
    elgamal: { type: 'Public-Key', subtype: 'Discrete Logarithm', security: '⭐⭐⭐⭐ Strong*', securityLevel: 4, isAsymmetric: true },
    ecc: { type: 'Public-Key', subtype: 'Elliptic Curve', security: '⭐⭐⭐⭐⭐ Strong*', securityLevel: 5, isAsymmetric: true }
};

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
    },

    // -------------------------------------------------------------------------
    // DES (Data Encryption Standard)
    // -------------------------------------------------------------------------
    des: {
        name: 'DES (Data Encryption Standard)',
        formula: '64-bit block, 56-bit key, 16 Feistel rounds',
        description: 'Legacy symmetric block cipher using Feistel network with S-boxes and permutations.',
        hint: 'DES processes 64-bit blocks through 16 rounds. Each round uses expansion, S-box substitution, and permutation. Key is 64 bits (8 bytes) with 8 parity bits.',
        
        // DES Tables (abbreviated - full implementation would be larger)
        IP: [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7],
        FP: [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25],
        E: [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1],
        P: [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25],
        PC1: [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4],
        PC2: [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32],
        SHIFTS: [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1],
        S_BOXES: [
            [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
            [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
            [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
            [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
            [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
            [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
            [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
            [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
        ],

        hexToBinary(hex) {
            return hex.split('').map(h => parseInt(h, 16).toString(2).padStart(4, '0')).join('');
        },
        
        binaryToHex(binary) {
            let hex = '';
            for (let i = 0; i < binary.length; i += 4) {
                hex += parseInt(binary.substr(i, 4), 2).toString(16);
            }
            return hex.toUpperCase();
        },
        
        permute(input, table) {
            return table.map(pos => input[pos - 1]).join('');
        },
        
        leftShift(bits, n) {
            return bits.slice(n) + bits.slice(0, n);
        },
        
        xor(a, b) {
            return a.split('').map((bit, i) => (bit ^ b[i]).toString()).join('');
        },
        
        generateKeys(key) {
            const keyBinary = this.hexToBinary(key);
            const permutedKey = this.permute(keyBinary, this.PC1);
            let C = permutedKey.slice(0, 28);
            let D = permutedKey.slice(28, 56);
            const roundKeys = [];
            for (let i = 0; i < 16; i++) {
                C = this.leftShift(C, this.SHIFTS[i]);
                D = this.leftShift(D, this.SHIFTS[i]);
                roundKeys.push(this.permute(C + D, this.PC2));
            }
            return roundKeys;
        },
        
        feistel(R, roundKey) {
            const expanded = this.permute(R, this.E);
            const xored = this.xor(expanded, roundKey);
            let sBoxOutput = '';
            for (let i = 0; i < 8; i++) {
                const block = xored.substr(i * 6, 6);
                const row = parseInt(block[0] + block[5], 2);
                const col = parseInt(block.substr(1, 4), 2);
                sBoxOutput += this.S_BOXES[i][row][col].toString(2).padStart(4, '0');
            }
            return this.permute(sBoxOutput, this.P);
        },
        
        desCore(block, keys) {
            const permuted = this.permute(block, this.IP);
            let L = permuted.slice(0, 32);
            let R = permuted.slice(32, 64);
            for (let i = 0; i < 16; i++) {
                const newL = R;
                const f = this.feistel(R, keys[i]);
                const newR = this.xor(L, f);
                L = newL;
                R = newR;
            }
            return this.permute(R + L, this.FP);
        },
        
        stringToBytes(str) {
            return str.split('').map(c => c.charCodeAt(0));
        },
        
        bytesToString(bytes) {
            return bytes.map(b => String.fromCharCode(b)).join('');
        },
        
        bytesToHex(bytes) {
            return bytes.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        },
        
        hexToBytes(hex) {
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) {
                bytes.push(parseInt(hex.substr(i, 2), 16));
            }
            return bytes;
        },
        
        padBytes(bytes) {
            const blockSize = 8;
            const padLen = blockSize - (bytes.length % blockSize);
            return bytes.concat(Array(padLen).fill(padLen));
        },
        
        unpadBytes(bytes) {
            const padLen = bytes[bytes.length - 1];
            if (padLen > 0 && padLen <= 8) {
                return bytes.slice(0, -padLen);
            }
            return bytes;
        },
        
        encrypt(plaintext, key) {
            if (!/^[0-9A-Fa-f]{16}$/.test(key)) {
                throw new Error('Key must be exactly 16 hexadecimal characters');
            }
            const keys = this.generateKeys(key);
            const plaintextBytes = this.padBytes(this.stringToBytes(plaintext));
            let ciphertext = [];
            for (let i = 0; i < plaintextBytes.length; i += 8) {
                const blockBytes = plaintextBytes.slice(i, i + 8);
                const blockHex = this.bytesToHex(blockBytes);
                const block = this.hexToBinary(blockHex);
                const encrypted = this.desCore(block, keys);
                ciphertext.push(...this.hexToBytes(this.binaryToHex(encrypted)));
            }
            return this.bytesToHex(ciphertext);
        },
        
        decrypt(ciphertext, key) {
            if (!/^[0-9A-Fa-f]{16}$/.test(key)) {
                throw new Error('Key must be exactly 16 hexadecimal characters');
            }
            if (!/^[0-9A-Fa-f]+$/.test(ciphertext) || ciphertext.length % 16 !== 0) {
                throw new Error('Invalid ciphertext format');
            }
            const keys = this.generateKeys(key).reverse();
            const ciphertextBytes = this.hexToBytes(ciphertext);
            let plaintextBytes = [];
            for (let i = 0; i < ciphertextBytes.length; i += 8) {
                const blockBytes = ciphertextBytes.slice(i, i + 8);
                const blockHex = this.bytesToHex(blockBytes);
                const block = this.hexToBinary(blockHex);
                const decrypted = this.desCore(block, keys);
                plaintextBytes.push(...this.hexToBytes(this.binaryToHex(decrypted)));
            }
            return this.bytesToString(this.unpadBytes(plaintextBytes));
        }
    },

    // -------------------------------------------------------------------------
    // AES-128
    // -------------------------------------------------------------------------
    aes: {
        name: 'AES-128',
        formula: '128-bit block, 128-bit key, 10 SPN rounds',
        description: 'Modern symmetric block cipher using SubBytes, ShiftRows, MixColumns, and AddRoundKey.',
        hint: 'AES uses a Substitution-Permutation Network. Each round applies byte substitution (S-box), row shifting, column mixing (except last round), and key addition.',
        
        S_BOX: [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16],
        INV_S_BOX: [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d],
        RCON: [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36],
        
        hexToBytes(hex) {
            const bytes = [];
            for (let i = 0; i < hex.length; i += 2) {
                bytes.push(parseInt(hex.substr(i, 2), 16));
            }
            return bytes;
        },
        
        bytesToHex(bytes) {
            return bytes.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        },
        
        stringToBytes(str) {
            return str.split('').map(c => c.charCodeAt(0));
        },
        
        bytesToString(bytes) {
            return bytes.map(b => String.fromCharCode(b)).join('');
        },
        
        bytesToState(bytes) {
            const state = [];
            for (let c = 0; c < 4; c++) {
                state[c] = [];
                for (let r = 0; r < 4; r++) {
                    state[c][r] = bytes[c * 4 + r];
                }
            }
            return state;
        },
        
        stateToBytes(state) {
            const bytes = [];
            for (let c = 0; c < 4; c++) {
                for (let r = 0; r < 4; r++) {
                    bytes.push(state[c][r]);
                }
            }
            return bytes;
        },
        
        subBytes(state, inv = false) {
            const box = inv ? this.INV_S_BOX : this.S_BOX;
            for (let c = 0; c < 4; c++) {
                for (let r = 0; r < 4; r++) {
                    state[c][r] = box[state[c][r]];
                }
            }
            return state;
        },
        
        shiftRows(state, inv = false) {
            for (let r = 1; r < 4; r++) {
                const row = [state[0][r], state[1][r], state[2][r], state[3][r]];
                const shift = inv ? 4 - r : r;
                for (let c = 0; c < 4; c++) {
                    state[c][r] = row[(c + shift) % 4];
                }
            }
            return state;
        },
        
        xtime(a) {
            return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
        },
        
        gmul(a, b) {
            let result = 0;
            let temp = a;
            while (b > 0) {
                if (b & 1) result ^= temp;
                temp = this.xtime(temp);
                b >>= 1;
            }
            return result & 0xff;
        },
        
        mixColumns(state, inv = false) {
            for (let c = 0; c < 4; c++) {
                const a = state[c].slice();
                if (inv) {
                    state[c][0] = this.gmul(a[0],0x0e) ^ this.gmul(a[1],0x0b) ^ this.gmul(a[2],0x0d) ^ this.gmul(a[3],0x09);
                    state[c][1] = this.gmul(a[0],0x09) ^ this.gmul(a[1],0x0e) ^ this.gmul(a[2],0x0b) ^ this.gmul(a[3],0x0d);
                    state[c][2] = this.gmul(a[0],0x0d) ^ this.gmul(a[1],0x09) ^ this.gmul(a[2],0x0e) ^ this.gmul(a[3],0x0b);
                    state[c][3] = this.gmul(a[0],0x0b) ^ this.gmul(a[1],0x0d) ^ this.gmul(a[2],0x09) ^ this.gmul(a[3],0x0e);
                } else {
                    state[c][0] = this.gmul(a[0],2) ^ this.gmul(a[1],3) ^ a[2] ^ a[3];
                    state[c][1] = a[0] ^ this.gmul(a[1],2) ^ this.gmul(a[2],3) ^ a[3];
                    state[c][2] = a[0] ^ a[1] ^ this.gmul(a[2],2) ^ this.gmul(a[3],3);
                    state[c][3] = this.gmul(a[0],3) ^ a[1] ^ a[2] ^ this.gmul(a[3],2);
                }
            }
            return state;
        },
        
        addRoundKey(state, roundKey) {
            for (let c = 0; c < 4; c++) {
                for (let r = 0; r < 4; r++) {
                    state[c][r] ^= roundKey[c * 4 + r];
                }
            }
            return state;
        },
        
        keyExpansion(key) {
            const keyBytes = this.hexToBytes(key);
            const w = [];
            for (let i = 0; i < 4; i++) {
                w[i] = keyBytes.slice(i * 4, (i + 1) * 4);
            }
            for (let i = 4; i < 44; i++) {
                let temp = w[i - 1].slice();
                if (i % 4 === 0) {
                    temp = [temp[1], temp[2], temp[3], temp[0]].map(b => this.S_BOX[b]);
                    temp[0] ^= this.RCON[i / 4];
                }
                w[i] = w[i - 4].map((b, j) => b ^ temp[j]);
            }
            const roundKeys = [];
            for (let round = 0; round <= 10; round++) {
                const roundKey = [];
                for (let i = 0; i < 4; i++) {
                    roundKey.push(...w[round * 4 + i]);
                }
                roundKeys.push(roundKey);
            }
            return roundKeys;
        },
        
        encryptBlock(block, roundKeys) {
            let state = this.bytesToState(block);
            state = this.addRoundKey(state, roundKeys[0]);
            for (let round = 1; round <= 9; round++) {
                state = this.subBytes(state);
                state = this.shiftRows(state);
                state = this.mixColumns(state);
                state = this.addRoundKey(state, roundKeys[round]);
            }
            state = this.subBytes(state);
            state = this.shiftRows(state);
            state = this.addRoundKey(state, roundKeys[10]);
            return this.stateToBytes(state);
        },
        
        decryptBlock(block, roundKeys) {
            let state = this.bytesToState(block);
            state = this.addRoundKey(state, roundKeys[10]);
            for (let round = 9; round >= 1; round--) {
                state = this.shiftRows(state, true);
                state = this.subBytes(state, true);
                state = this.addRoundKey(state, roundKeys[round]);
                state = this.mixColumns(state, true);
            }
            state = this.shiftRows(state, true);
            state = this.subBytes(state, true);
            state = this.addRoundKey(state, roundKeys[0]);
            return this.stateToBytes(state);
        },
        
        padBytes(bytes, blockSize) {
            const padLen = blockSize - (bytes.length % blockSize);
            return bytes.concat(Array(padLen).fill(padLen));
        },
        
        unpadBytes(bytes) {
            const padLen = bytes[bytes.length - 1];
            if (padLen > 0 && padLen <= 16) {
                return bytes.slice(0, -padLen);
            }
            return bytes;
        },
        
        encrypt(plaintext, key) {
            if (!/^[0-9A-Fa-f]{32}$/.test(key)) {
                throw new Error('Key must be exactly 32 hexadecimal characters');
            }
            const roundKeys = this.keyExpansion(key);
            const plaintextBytes = this.padBytes(this.stringToBytes(plaintext), 16);
            let ciphertext = [];
            for (let i = 0; i < plaintextBytes.length; i += 16) {
                const block = plaintextBytes.slice(i, i + 16);
                const encrypted = this.encryptBlock(block, roundKeys);
                ciphertext.push(...encrypted);
            }
            return this.bytesToHex(ciphertext);
        },
        
        decrypt(ciphertext, key) {
            if (!/^[0-9A-Fa-f]{32}$/.test(key)) {
                throw new Error('Key must be exactly 32 hexadecimal characters');
            }
            if (!/^[0-9A-Fa-f]+$/.test(ciphertext) || ciphertext.length % 32 !== 0) {
                throw new Error('Invalid ciphertext format');
            }
            const roundKeys = this.keyExpansion(key);
            const ciphertextBytes = this.hexToBytes(ciphertext);
            let plaintextBytes = [];
            for (let i = 0; i < ciphertextBytes.length; i += 16) {
                const block = ciphertextBytes.slice(i, i + 16);
                const decrypted = this.decryptBlock(block, roundKeys);
                plaintextBytes.push(...decrypted);
            }
            return this.bytesToString(this.unpadBytes(plaintextBytes));
        }
    },

    // -------------------------------------------------------------------------
    // ElGamal Cryptosystem
    // -------------------------------------------------------------------------
    elgamal: {
        name: 'ElGamal Cryptosystem',
        formula: 'c₁ = gᵏ mod p, c₂ = m·yᵏ mod p',
        description: 'Public-key encryption based on the Discrete Logarithm Problem.',
        hint: 'Generate keys first. Encryption uses random k to create (c1, c2). Decryption recovers m using private key x. Each character is encrypted separately.',
        
        SAFE_PRIMES: [467n, 1019n, 2027n, 4079n, 7919n],
        currentKeys: null,
        
        modPow(base, exp, m) {
            if (m === 1n) return 0n;
            let result = 1n;
            base = base % m;
            while (exp > 0n) {
                if (exp % 2n === 1n) result = (result * base) % m;
                exp = exp / 2n;
                base = (base * base) % m;
            }
            return result;
        },
        
        modInverse(a, m) {
            let [old_r, r] = [a, m];
            let [old_s, s] = [1n, 0n];
            while (r !== 0n) {
                const quotient = old_r / r;
                [old_r, r] = [r, old_r - quotient * r];
                [old_s, s] = [s, old_s - quotient * s];
            }
            if (old_r !== 1n) return null;
            return ((old_s % m) + m) % m;
        },
        
        findPrimitiveRoot(p) {
            if (p === 2n) return 1n;
            const q = (p - 1n) / 2n;
            for (let g = 2n; g < p; g++) {
                if (this.modPow(g, 2n, p) !== 1n && this.modPow(g, q, p) !== 1n) {
                    return g;
                }
            }
            return 2n;
        },
        
        randomBigInt(min, max) {
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
        },
        
        generateKeys(primeIndex = 0) {
            const p = this.SAFE_PRIMES[primeIndex % this.SAFE_PRIMES.length];
            const g = this.findPrimitiveRoot(p);
            const x = this.randomBigInt(2n, p - 1n);
            const y = this.modPow(g, x, p);
            this.currentKeys = {
                publicKey: { p, g, y },
                privateKey: { x }
            };
            return this.currentKeys;
        },
        
        encrypt(plaintext, key) {
            if (!this.currentKeys) {
                throw new Error('Generate keys first');
            }
            const { p, g, y } = this.currentKeys.publicKey;
            const encrypted = [];
            for (const char of plaintext) {
                const m = BigInt(char.charCodeAt(0));
                if (m <= 0n || m >= p) {
                    throw new Error(`Character code ${m} out of range`);
                }
                const k = this.randomBigInt(2n, p - 1n);
                const c1 = this.modPow(g, k, p);
                const s = this.modPow(y, k, p);
                const c2 = (m * s) % p;
                encrypted.push(`${c1},${c2}`);
            }
            return encrypted.join(';');
        },
        
        decrypt(ciphertext, key) {
            if (!this.currentKeys) {
                throw new Error('Generate keys first');
            }
            const { p } = this.currentKeys.publicKey;
            const { x } = this.currentKeys.privateKey;
            const pairs = ciphertext.split(';');
            let plaintext = '';
            for (const pair of pairs) {
                const [c1Str, c2Str] = pair.split(',');
                const c1 = BigInt(c1Str);
                const c2 = BigInt(c2Str);
                const s = this.modPow(c1, x, p);
                const sInverse = this.modInverse(s, p);
                const m = (c2 * sInverse) % p;
                plaintext += String.fromCharCode(Number(m));
            }
            return plaintext;
        }
    },

    // -------------------------------------------------------------------------
    // ECC (Elliptic Curve Cryptography)
    // -------------------------------------------------------------------------
    ecc: {
        name: 'ECC (Elliptic Curve)',
        formula: 'y² = x³ + ax + b (mod p)',
        description: 'Public-key cryptography using elliptic curves over finite fields.',
        hint: 'Uses small demo curves. Generate keys first. Encrypts small numbers (character codes). ECDH creates shared secrets from public key exchange.',
        
        CURVES: {
            tiny: { a: 1n, b: 6n, p: 11n, G: { x: 2n, y: 7n }, n: 7n },
            small: { a: 1n, b: 1n, p: 167n, G: { x: 2n, y: 41n }, n: 144n },
            secp: { a: 0n, b: 7n, p: 17n, G: { x: 15n, y: 13n }, n: 18n }
        },
        currentKeys: null,
        currentCurve: null,
        
        modInverse(a, p) {
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
        },
        
        isInfinity(P) {
            return P.x === null && P.y === null;
        },
        
        pointAdd(P, Q, curve) {
            if (this.isInfinity(P)) return Q;
            if (this.isInfinity(Q)) return P;
            const { p, a } = curve;
            if (P.x === Q.x && ((P.y + Q.y) % p === 0n)) {
                return { x: null, y: null };
            }
            let lambda;
            if (P.x === Q.x && P.y === Q.y) {
                const num = (3n * P.x * P.x + a) % p;
                const den = (2n * P.y) % p;
                const denInv = this.modInverse(den, p);
                if (denInv === null) return { x: null, y: null };
                lambda = (num * denInv) % p;
            } else {
                const num = ((Q.y - P.y) % p + p) % p;
                const den = ((Q.x - P.x) % p + p) % p;
                const denInv = this.modInverse(den, p);
                if (denInv === null) return { x: null, y: null };
                lambda = (num * denInv) % p;
            }
            let x3 = (lambda * lambda - P.x - Q.x) % p;
            let y3 = (lambda * (P.x - x3) - P.y) % p;
            x3 = ((x3 % p) + p) % p;
            y3 = ((y3 % p) + p) % p;
            return { x: x3, y: y3 };
        },
        
        scalarMult(k, P, curve) {
            if (k === 0n || this.isInfinity(P)) {
                return { x: null, y: null };
            }
            let result = { x: null, y: null };
            let addend = { x: P.x, y: P.y };
            while (k > 0n) {
                if (k % 2n === 1n) {
                    result = this.pointAdd(result, addend, curve);
                }
                addend = this.pointAdd(addend, addend, curve);
                k = k / 2n;
            }
            return result;
        },
        
        randomBigInt(min, max) {
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
        },
        
        generateKeys(curveName = 'small') {
            const curve = this.CURVES[curveName];
            this.currentCurve = curve;
            const d = this.randomBigInt(1n, curve.n);
            const Q = this.scalarMult(d, curve.G, curve);
            this.currentKeys = {
                publicKey: { Q, curve },
                privateKey: { d }
            };
            return this.currentKeys;
        },
        
        encodeToPoint(m, curve) {
            const message = BigInt(m);
            for (let x = message; x < message + 100n; x++) {
                const ySquared = (x * x * x + curve.a * x + curve.b) % curve.p;
                for (let y = 0n; y < curve.p; y++) {
                    if ((y * y) % curve.p === ySquared) {
                        return { point: { x: x % curve.p, y }, offset: x - message };
                    }
                }
            }
            throw new Error(`Cannot encode ${m} to curve point`);
        },
        
        encrypt(plaintext, key) {
            if (!this.currentKeys || !this.currentCurve) {
                throw new Error('Generate keys first');
            }
            const curve = this.currentCurve;
            const { Q } = this.currentKeys.publicKey;
            const encrypted = [];
            for (const char of plaintext) {
                const m = char.charCodeAt(0);
                const { point: M, offset } = this.encodeToPoint(m, curve);
                
                // Find a k that doesn't produce infinity
                let k, C1, kQ, C2;
                let attempts = 0;
                do {
                    k = this.randomBigInt(1n, curve.n - 1n);
                    C1 = this.scalarMult(k, curve.G, curve);
                    kQ = this.scalarMult(k, Q, curve);
                    C2 = this.pointAdd(M, kQ, curve);
                    attempts++;
                } while ((this.isInfinity(C1) || this.isInfinity(C2)) && attempts < 100);
                
                if (this.isInfinity(C1) || this.isInfinity(C2)) {
                    throw new Error('Encryption failed - try a different curve');
                }
                
                encrypted.push(`${C1.x},${C1.y};${C2.x},${C2.y};${offset}`);
            }
            return encrypted.join('|');
        },
        
        decrypt(ciphertext, key) {
            if (!this.currentKeys || !this.currentCurve) {
                throw new Error('Generate keys first');
            }
            const curve = this.currentCurve;
            const { d } = this.currentKeys.privateKey;
            const parts = ciphertext.split('|');
            let plaintext = '';
            for (const part of parts) {
                const [c1Str, c2Str, offsetStr] = part.split(';');
                const [c1x, c1y] = c1Str.split(',').map(s => BigInt(s));
                const [c2x, c2y] = c2Str.split(',').map(s => BigInt(s));
                const offset = BigInt(offsetStr);
                const C1 = { x: c1x, y: c1y };
                const C2 = { x: c2x, y: c2y };
                const dC1 = this.scalarMult(d, C1, curve);
                const negDC1 = { x: dC1.x, y: (curve.p - dC1.y) % curve.p };
                const M = this.pointAdd(C2, negDC1, curve);
                const m = M.x - offset;
                plaintext += String.fromCharCode(Number(m));
            }
            return plaintext;
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
            
            case 'des':
                if (!key || key.length === 0) return { valid: false, message: 'Enter hexadecimal key' };
                if (!/^[0-9A-Fa-f]+$/.test(key)) return { valid: false, message: 'Key must contain only hex characters (0-9, A-F)' };
                if (key.length !== 16) return { valid: false, message: `Key must be 16 hex chars (currently ${key.length})` };
                return { valid: true, message: 'Valid 64-bit DES key' };
            
            case 'aes':
                if (!key || key.length === 0) return { valid: false, message: 'Enter hexadecimal key' };
                if (!/^[0-9A-Fa-f]+$/.test(key)) return { valid: false, message: 'Key must contain only hex characters (0-9, A-F)' };
                if (key.length !== 32) return { valid: false, message: `Key must be 32 hex chars (currently ${key.length})` };
                return { valid: true, message: 'Valid 128-bit AES key' };
            
            case 'elgamal':
                if (!algorithms.elgamal.currentKeys) return { valid: false, message: 'Generate keys first' };
                return { valid: true, message: `Keys ready (p=${algorithms.elgamal.currentKeys.publicKey.p})` };
            
            case 'ecc':
                if (!algorithms.ecc.currentKeys) return { valid: false, message: 'Generate keys first' };
                return { valid: true, message: `Keys ready (curve p=${algorithms.ecc.currentCurve.p})` };
                
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
            tagType: document.getElementById('tag-type'),
            tagSubtype: document.getElementById('tag-subtype'),
            tagSecurity: document.getElementById('tag-security'),
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
            hillDet: document.getElementById('hill-det'),
            
            // Hex key (DES/AES)
            keyHex: document.getElementById('key-hex'),
            keyHexText: document.getElementById('key-hex-text'),
            keyHexHint: document.getElementById('key-hex-hint'),
            hexCount: document.getElementById('hex-count'),
            hexRequired: document.getElementById('hex-required'),
            
            // ElGamal
            keyElgamal: document.getElementById('key-elgamal'),
            elgamalPrime: document.getElementById('elgamal-prime'),
            btnGenElgamal: document.getElementById('btn-gen-elgamal'),
            elgamalKeys: document.getElementById('elgamal-keys'),
            elgamalP: document.getElementById('elgamal-p'),
            elgamalG: document.getElementById('elgamal-g'),
            elgamalY: document.getElementById('elgamal-y'),
            elgamalX: document.getElementById('elgamal-x'),
            
            // ECC
            keyEcc: document.getElementById('key-ecc'),
            eccCurve: document.getElementById('ecc-curve'),
            btnGenEcc: document.getElementById('btn-gen-ecc'),
            eccKeys: document.getElementById('ecc-keys'),
            eccA: document.getElementById('ecc-a'),
            eccB: document.getElementById('ecc-b'),
            eccP: document.getElementById('ecc-p'),
            eccGx: document.getElementById('ecc-gx'),
            eccGy: document.getElementById('ecc-gy'),
            eccQx: document.getElementById('ecc-qx'),
            eccQy: document.getElementById('ecc-qy'),
            eccD: document.getElementById('ecc-d')
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
        columnar: 'text',
        des: 'hex',
        aes: 'hex',
        elgamal: 'elgamal',
        ecc: 'ecc'
    },
    
    // Key hints
    keyHints: {
        caesar: 'Shift value (0-25)',
        multiplicative: 'Must be coprime with 26',
        railfence: 'Number of rails (minimum 2)',
        vigenere: 'Keyword (letters only, will repeat)',
        autokey: 'Initial keyword (plaintext extends key)',
        playfair: 'Keyword for building 5×5 matrix',
        columnar: 'Keyword determines column read order',
        des: '16 hex characters (64-bit key)',
        aes: '32 hex characters (128-bit key)'
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
        
        // Hex key input (DES/AES)
        this.elements.keyHexText.addEventListener('input', () => {
            this.updateHexCounter();
            this.validateAndUpdate();
        });
        
        // ElGamal key generation
        this.elements.btnGenElgamal.addEventListener('click', () => {
            this.generateElgamalKeys();
        });
        
        // ECC key generation
        this.elements.btnGenEcc.addEventListener('click', () => {
            this.generateEccKeys();
        });
    },
    
    generateElgamalKeys() {
        const primeIndex = parseInt(this.elements.elgamalPrime.value);
        const keys = algorithms.elgamal.generateKeys(primeIndex);
        
        this.elements.elgamalP.textContent = keys.publicKey.p.toString();
        this.elements.elgamalG.textContent = keys.publicKey.g.toString();
        this.elements.elgamalY.textContent = keys.publicKey.y.toString();
        this.elements.elgamalX.textContent = keys.privateKey.x.toString();
        this.elements.elgamalKeys.classList.remove('hidden');
        
        this.validateAndUpdate();
    },
    
    generateEccKeys() {
        const curveName = this.elements.eccCurve.value;
        const keys = algorithms.ecc.generateKeys(curveName);
        const curve = algorithms.ecc.currentCurve;
        
        this.elements.eccA.textContent = curve.a.toString();
        this.elements.eccB.textContent = curve.b.toString();
        this.elements.eccP.textContent = curve.p.toString();
        this.elements.eccGx.textContent = curve.G.x.toString();
        this.elements.eccGy.textContent = curve.G.y.toString();
        this.elements.eccQx.textContent = keys.publicKey.Q.x.toString();
        this.elements.eccQy.textContent = keys.publicKey.Q.y.toString();
        this.elements.eccD.textContent = keys.privateKey.d.toString();
        this.elements.eccKeys.classList.remove('hidden');
        
        this.validateAndUpdate();
    },
    
    updateHexCounter() {
        const algo = this.elements.algorithmSelect.value;
        const hexText = this.elements.keyHexText.value.replace(/[^0-9A-Fa-f]/g, '');
        const required = algo === 'aes' ? 32 : 16;
        
        this.elements.hexCount.textContent = hexText.length;
        this.elements.hexRequired.textContent = required;
    },
    
    updateAlgorithmUI() {
        const algo = this.elements.algorithmSelect.value;
        const algoData = algorithms[algo];
        const classification = algorithmClassification[algo];
        
        // Update info card
        this.elements.algoName.textContent = algoData.name;
        this.elements.algoFormula.textContent = algoData.formula;
        this.elements.algoDesc.textContent = algoData.description;
        this.elements.eduHintText.textContent = algoData.hint;
        
        // Update classification tags
        this.elements.tagType.textContent = classification.type;
        this.elements.tagSubtype.textContent = classification.subtype;
        this.elements.tagSecurity.textContent = classification.security;
        
        // Update security tag color
        this.elements.tagSecurity.classList.remove('security-high');
        if (classification.securityLevel >= 5) {
            this.elements.tagSecurity.classList.add('security-high');
        }
        
        // Hide all key inputs
        this.elements.keyNumber.classList.add('hidden');
        this.elements.keyAffine.classList.add('hidden');
        this.elements.keyText.classList.add('hidden');
        this.elements.keyOtp.classList.add('hidden');
        this.elements.keyMono.classList.add('hidden');
        this.elements.keyHill.classList.add('hidden');
        this.elements.keyHex.classList.add('hidden');
        this.elements.keyElgamal.classList.add('hidden');
        this.elements.keyEcc.classList.add('hidden');
        
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
            case 'hex':
                this.elements.keyHex.classList.remove('hidden');
                this.elements.keyHexHint.textContent = this.keyHints[algo] || '';
                this.elements.hexRequired.textContent = algo === 'aes' ? '32' : '16';
                this.updateHexCounter();
                break;
            case 'elgamal':
                this.elements.keyElgamal.classList.remove('hidden');
                break;
            case 'ecc':
                this.elements.keyEcc.classList.remove('hidden');
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
            
            case 'hex':
                return this.elements.keyHexText.value.replace(/[^0-9A-Fa-f]/g, '');
            
            case 'elgamal':
                return algorithms.elgamal.currentKeys ? 'generated' : null;
            
            case 'ecc':
                return algorithms.ecc.currentKeys ? 'generated' : null;
                
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
