/**
 * ملف: playfair.js
 * الوصف: شيفرة بلايفير (Playfair Cipher)
 * 
 * آلية العمل:
 * - تستخدم مصفوفة 5×5 مبنية من كلمة مفتاحية
 * - الحرفان I و J يُعاملان كحرف واحد
 * - تُشفر الأحرف على شكل أزواج (digraphs)
 * 
 * قواعد التشفير للزوج (a, b):
 * 1. نفس الصف: كل حرف يُستبدل بالحرف الذي على يمينه
 * 2. نفس العمود: كل حرف يُستبدل بالحرف الذي أسفله
 * 3. مستطيل: كل حرف يُستبدل بالحرف في نفس صفه وعمود الحرف الآخر
 */

// استيراد الدوال المساعدة
const { isLetter } = require('../helpers');

/**
 * بناء مصفوفة 5×5 من الكلمة المفتاحية
 * @param {string} key - الكلمة المفتاحية
 * @returns {string[][]} - مصفوفة 5×5
 */
function generateMatrix(key) {
  const seen = new Set();
  const matrix = [];
  
  // تطبيع المفتاح: أحرف كبيرة، استبدال J بـ I، إزالة التكرارات
  // ثم إضافة بقية الأبجدية (بدون J)
  const keyChars = (key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')
    .toUpperCase()
    .replace(/J/g, 'I')
    .split('')
    .filter(c => {
      // تصفية: فقط الأحرف غير المكررة
      if (!isLetter(c) || seen.has(c)) return false;
      seen.add(c);
      return true;
    });
  
  // بناء المصفوفة 5×5
  for (let i = 0; i < 5; i++) {
    matrix.push(keyChars.slice(i * 5, i * 5 + 5));
  }
  
  return matrix;
}

/**
 * إيجاد موقع حرف في المصفوفة
 * @param {string[][]} matrix - المصفوفة
 * @param {string} char - الحرف المطلوب
 * @returns {{row: number, col: number}|null} - موقع الحرف
 */
function findPosition(matrix, char) {
  // استبدال J بـ I لأنهما متماثلان في هذه الشيفرة
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

/**
 * تحضير النص للتشفير
 * تقسيمه إلى أزواج مع معالجة الحالات الخاصة
 * @param {string} text - النص الأصلي
 * @returns {string[][]} - مصفوفة من الأزواج
 */
function prepareText(text) {
  // استخراج الأحرف فقط، تحويلها لأحرف كبيرة، استبدال J بـ I
  const letters = text.toUpperCase().split('').filter(isLetter).join('').replace(/J/g, 'I');
  
  // إنشاء الأزواج مع إدراج X بين الحروف المتكررة
  const digraphs = [];
  let i = 0;
  
  while (i < letters.length) {
    const first = letters[i];
    let second;
    
    if (i + 1 >= letters.length) {
      // طول فردي: إضافة X كحشو
      second = 'X';
      i++;
    } else if (letters[i] === letters[i + 1]) {
      // حرفان متماثلان: إدراج X بينهما
      second = 'X';
      i++;
    } else {
      // حالة عادية
      second = letters[i + 1];
      i += 2;
    }
    
    digraphs.push([first, second]);
  }
  
  return digraphs;
}

/**
 * تشفير زوج من الأحرف
 * @param {string[][]} matrix - المصفوفة
 * @param {string} a - الحرف الأول
 * @param {string} b - الحرف الثاني
 * @returns {string[]} - الزوج المشفر
 */
function encryptDigraph(matrix, a, b) {
  const posA = findPosition(matrix, a);
  const posB = findPosition(matrix, b);
  
  if (posA.row === posB.row) {
    // الحالة 1: نفس الصف - إزاحة لليمين
    return [
      matrix[posA.row][(posA.col + 1) % 5],
      matrix[posB.row][(posB.col + 1) % 5]
    ];
  } else if (posA.col === posB.col) {
    // الحالة 2: نفس العمود - إزاحة للأسفل
    return [
      matrix[(posA.row + 1) % 5][posA.col],
      matrix[(posB.row + 1) % 5][posB.col]
    ];
  } else {
    // الحالة 3: مستطيل - تبديل الأعمدة
    return [
      matrix[posA.row][posB.col],
      matrix[posB.row][posA.col]
    ];
  }
}

/**
 * فك تشفير زوج من الأحرف
 * @param {string[][]} matrix - المصفوفة
 * @param {string} a - الحرف الأول
 * @param {string} b - الحرف الثاني
 * @returns {string[]} - الزوج المفكك
 */
function decryptDigraph(matrix, a, b) {
  const posA = findPosition(matrix, a);
  const posB = findPosition(matrix, b);
  
  if (posA.row === posB.row) {
    // نفس الصف - إزاحة لليسار (عكس التشفير)
    return [
      matrix[posA.row][(posA.col + 4) % 5],  // +4 mod 5 = -1 mod 5
      matrix[posB.row][(posB.col + 4) % 5]
    ];
  } else if (posA.col === posB.col) {
    // نفس العمود - إزاحة للأعلى (عكس التشفير)
    return [
      matrix[(posA.row + 4) % 5][posA.col],
      matrix[(posB.row + 4) % 5][posB.col]
    ];
  } else {
    // مستطيل - تبديل الأعمدة (نفس عملية التشفير)
    return [
      matrix[posA.row][posB.col],
      matrix[posB.row][posA.col]
    ];
  }
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - الكلمة المفتاحية
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  const matrix = generateMatrix(key);
  const digraphs = prepareText(plaintext);
  
  // تتبع الأحرف الأصلية وحالاتها
  const originalChars = plaintext.split('');
  const letterCases = originalChars.filter(isLetter).map(c => c === c.toUpperCase());
  
  // تشفير جميع الأزواج
  const encryptedLetters = digraphs
    .map(([a, b]) => encryptDigraph(matrix, a, b))
    .flat();
  
  // إعادة بناء النص مع الحفاظ على البنية الأصلية
  let letterIndex = 0;
  let result = '';
  
  for (const char of originalChars) {
    if (!isLetter(char)) {
      result += char;  // إبقاء الأحرف غير الأبجدية
    } else if (letterIndex < encryptedLetters.length) {
      const encrypted = encryptedLetters[letterIndex];
      result += letterCases[letterIndex] ? encrypted : encrypted.toLowerCase();
      letterIndex++;
    }
  }
  
  // إضافة أحرف الحشو الإضافية
  while (letterIndex < encryptedLetters.length) {
    result += encryptedLetters[letterIndex];
    letterIndex++;
  }
  
  return result;
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {string} key - الكلمة المفتاحية
 * @returns {string} - النص الأصلي (قد يحتوي على X إضافية)
 */
function decrypt(ciphertext, key) {
  const matrix = generateMatrix(key);
  
  // استخراج الأحرف وحالاتها
  const originalChars = ciphertext.split('');
  const letters = originalChars.filter(isLetter);
  const letterCases = letters.map(c => c === c.toUpperCase());
  const upperLetters = letters.map(c => c.toUpperCase().replace(/J/g, 'I')).join('');
  
  // تقسيم إلى أزواج
  const digraphs = [];
  for (let i = 0; i < upperLetters.length; i += 2) {
    if (i + 1 < upperLetters.length) {
      digraphs.push([upperLetters[i], upperLetters[i + 1]]);
    } else {
      digraphs.push([upperLetters[i], 'X']);
    }
  }
  
  // فك تشفير الأزواج
  const decryptedLetters = digraphs
    .map(([a, b]) => decryptDigraph(matrix, a, b))
    .flat()
    .slice(0, letters.length);
  
  // إعادة بناء النص
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

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const playfair = require('./playfair');
// console.log(playfair.encrypt("HELLO", "MONARCHY"));  // CFSUPM
// console.log(playfair.decrypt("CFSUPM", "MONARCHY"));  // HELXLO (X مدرجة)
