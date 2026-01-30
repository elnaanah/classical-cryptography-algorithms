/**
 * ملف: hill.js
 * الوصف: شيفرة هيل (Hill Cipher)
 * 
 * آلية العمل:
 * - تستخدم ضرب المصفوفات لتشفير كتل من الأحرف
 * - التشفير: C = K × P mod 26 (ضرب مصفوفة × متجه)
 * - فك التشفير: P = K⁻¹ × C mod 26
 * 
 * المفتاح: مصفوفة مربعة (2×2 أو 3×3) قابلة للعكس في mod 26
 * شرط صلاحية المفتاح: محدد المصفوفة يجب أن يكون أولياً مع 26
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod, modInverse } = require('../helpers');

/**
 * دالة التحقق من صحة المفتاح (المصفوفة)
 * @param {number[][]} key - مصفوفة مربعة n×n
 * @returns {number[][]} - المصفوفة إذا كانت صالحة
 * @throws {Error} - إذا كانت المصفوفة غير صالحة أو غير قابلة للعكس
 */
function validateKey(key) {
  // التحقق من أن المفتاح مصفوفة غير فارغة
  if (!Array.isArray(key) || key.length === 0) {
    throw new Error('Key must be a non-empty 2D array (square matrix)');
  }
  
  const n = key.length;
  
  // التحقق من أن المصفوفة مربعة وجميع العناصر أرقام
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
  
  // حساب محدد المصفوفة والتحقق من إمكانية العكس
  const det = determinant(key);
  const detMod = mod(det, 26);
  const detInverse = modInverse(detMod, 26);
  
  // إذا لم يوجد معكوس للمحدد، المصفوفة غير صالحة
  if (detInverse === null) {
    throw new Error('Matrix is not invertible mod 26 (determinant must be coprime with 26)');
  }
  
  return key;
}

/**
 * حساب محدد المصفوفة (Determinant)
 * @param {number[][]} matrix - المصفوفة
 * @returns {number} - قيمة المحدد
 */
function determinant(matrix) {
  const n = matrix.length;
  
  // الحالة الأساسية: مصفوفة 1×1
  if (n === 1) {
    return matrix[0][0];
  }
  
  // الحالة الأساسية: مصفوفة 2×2
  // المحدد = ad - bc للمصفوفة [[a,b],[c,d]]
  if (n === 2) {
    return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
  }
  
  // للمصفوفات الأكبر: استخدام التوسيع بالعوامل المرافقة
  let det = 0;
  for (let col = 0; col < n; col++) {
    det += matrix[0][col] * cofactor(matrix, 0, col);
  }
  return det;
}

/**
 * حساب العامل المرافق (Cofactor) لعنصر في المصفوفة
 * @param {number[][]} matrix - المصفوفة
 * @param {number} row - رقم الصف
 * @param {number} col - رقم العمود
 * @returns {number} - العامل المرافق
 */
function cofactor(matrix, row, col) {
  // الحصول على المصفوفة الصغرى (بحذف الصف والعمود)
  const minor = getMinor(matrix, row, col);
  
  // الإشارة تتبادل: (+) إذا كان (row+col) زوجياً، (-) إذا كان فردياً
  const sign = ((row + col) % 2 === 0) ? 1 : -1;
  
  return sign * determinant(minor);
}

/**
 * الحصول على المصفوفة الصغرى (Minor Matrix)
 * بحذف صف وعمود محددين
 * @param {number[][]} matrix - المصفوفة الأصلية
 * @param {number} row - الصف المراد حذفه
 * @param {number} col - العمود المراد حذفه
 * @returns {number[][]} - المصفوفة الصغرى
 */
function getMinor(matrix, row, col) {
  return matrix
    .filter((_, i) => i !== row)  // حذف الصف
    .map(r => r.filter((_, j) => j !== col));  // حذف العمود من كل صف
}

/**
 * حساب معكوس المصفوفة في mod 26
 * @param {number[][]} matrix - المصفوفة الأصلية
 * @returns {number[][]} - المصفوفة المعكوسة
 */
function matrixInverseMod26(matrix) {
  const n = matrix.length;
  
  // حساب المحدد ومعكوسه
  const det = determinant(matrix);
  const detMod = mod(det, 26);
  const detInverse = modInverse(detMod, 26);
  
  // حساب المصفوفة المرافقة المنقولة (Adjugate Matrix)
  // Adjugate = transpose of cofactor matrix
  const adjugate = [];
  for (let i = 0; i < n; i++) {
    adjugate.push([]);
    for (let j = 0; j < n; j++) {
      // ملاحظة: adjugate[i][j] = cofactor[j][i] (منقولة)
      // ثم نضرب في معكوس المحدد
      adjugate[i].push(mod(cofactor(matrix, j, i) * detInverse, 26));
    }
  }
  
  return adjugate;
}

/**
 * ضرب مصفوفة في متجه
 * @param {number[][]} matrix - المصفوفة
 * @param {number[]} vector - المتجه
 * @returns {number[]} - المتجه الناتج
 */
function multiplyMatrixVector(matrix, vector) {
  const n = matrix.length;
  const result = [];
  
  // كل عنصر في الناتج = حاصل الضرب النقطي للصف في المتجه
  for (let i = 0; i < n; i++) {
    let sum = 0;
    for (let j = 0; j < n; j++) {
      sum += matrix[i][j] * vector[j];
    }
    result.push(mod(sum, 26));
  }
  
  return result;
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {number[][]} key - مصفوفة المفتاح
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  const matrix = validateKey(key);
  const n = matrix.length;  // حجم الكتلة (2 للمصفوفة 2×2، 3 للمصفوفة 3×3)
  
  // استخراج الأحرف وحالاتها
  const originalChars = plaintext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  
  // تحويل الأحرف إلى أرقام
  let nums = letters.map(c => letterToNum(c));
  
  // إضافة حشو (padding) بالحرف X إذا لزم الأمر
  // لجعل طول النص من مضاعفات حجم الكتلة
  while (nums.length % n !== 0) {
    nums.push(23); // X = 23
    letterCases.push(true); // حرف كبير للحشو
  }
  
  // تشفير الكتل
  const encryptedNums = [];
  for (let i = 0; i < nums.length; i += n) {
    // استخراج كتلة من n أحرف
    const block = nums.slice(i, i + n);
    
    // تشفير الكتلة بضرب المصفوفة في المتجه
    const encryptedBlock = multiplyMatrixVector(matrix, block);
    encryptedNums.push(...encryptedBlock);
  }
  
  // إعادة بناء النص مع الحفاظ على البنية الأصلية
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;  // إبقاء الأحرف غير الأبجدية
    } else if (letterIndex < encryptedNums.length) {
      const encrypted = numToLetter(encryptedNums[letterIndex]);
      result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  // إضافة أحرف الحشو في النهاية
  while (letterIndex < encryptedNums.length) {
    const encrypted = numToLetter(encryptedNums[letterIndex]);
    result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
    letterIndex++;
  }
  
  return result;
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {number[][]} key - مصفوفة المفتاح
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  const matrix = validateKey(key);
  const n = matrix.length;
  
  // حساب معكوس المصفوفة لفك التشفير
  const inverseMatrix = matrixInverseMod26(matrix);
  
  // استخراج الأحرف وحالاتها
  const originalChars = ciphertext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  
  // تحويل الأحرف إلى أرقام
  let nums = letters.map(c => letterToNum(c));
  
  // إضافة حشو إذا لزم (لا يحدث عادةً مع نص مشفر صحيح)
  while (nums.length % n !== 0) {
    nums.push(23);
    letterCases.push(true);
  }
  
  // فك تشفير الكتل باستخدام المصفوفة المعكوسة
  const decryptedNums = [];
  for (let i = 0; i < nums.length; i += n) {
    const block = nums.slice(i, i + n);
    const decryptedBlock = multiplyMatrixVector(inverseMatrix, block);
    decryptedNums.push(...decryptedBlock);
  }
  
  // إعادة بناء النص
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

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const hill = require('./hill');
// const key2x2 = [[6, 24], [1, 16]]; // مثال على مفتاح 2×2
// console.log(hill.encrypt("HELP", key2x2));  // DELR (يعتمد على المفتاح)
// console.log(hill.decrypt(hill.encrypt("HELP", key2x2), key2x2));  // HELP
