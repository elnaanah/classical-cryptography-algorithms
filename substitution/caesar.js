/**
 * ملف: caesar.js
 * الوصف: تشفير قيصر (شيفرة الإزاحة / الشيفرة الجمعية)
 * 
 * آلية العمل:
 * - التشفير: كل حرف يُزاح بمقدار المفتاح (k) في الأبجدية
 *   المعادلة: C = (P + k) mod 26
 * - فك التشفير: كل حرف يُزاح عكسياً بمقدار المفتاح
 *   المعادلة: P = (C - k) mod 26
 * 
 * مثال: إذا كان المفتاح = 3، فإن A تصبح D، و B تصبح E، وهكذا
 */

// استيراد الدوال المساعدة من ملف helpers
const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي المراد تشفيره
 * @param {number} key - مفتاح التشفير (مقدار الإزاحة)
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  // تطبيق mod 26 على المفتاح لضمان أنه ضمن نطاق الأبجدية
  const k = mod(key, 26);
  
  return plaintext.split('').map(char => {
    // إبقاء الأحرف غير الأبجدية (مسافات، أرقام، رموز) كما هي
    if (!isLetter(char)) return char;
    
    // تحويل الحرف إلى رقم (A=0, B=1, ..., Z=25)
    const p = letterToNum(char);
    
    // تطبيق معادلة التشفير: C = (P + k) mod 26
    const c = mod(p + k, 26);
    
    // الحفاظ على حالة الحرف (كبير/صغير)
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {number} key - مفتاح التشفير (نفس المفتاح المستخدم في التشفير)
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  // تطبيق mod 26 على المفتاح
  const k = mod(key, 26);
  
  return ciphertext.split('').map(char => {
    // إبقاء الأحرف غير الأبجدية كما هي
    if (!isLetter(char)) return char;
    
    // تحويل الحرف المشفر إلى رقم
    const c = letterToNum(char);
    
    // تطبيق معادلة فك التشفير: P = (C - k) mod 26
    const p = mod(c - k, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

// تصدير الدوال للاستخدام في ملفات أخرى
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const caesar = require('./caesar');
// console.log(caesar.encrypt("HELLO", 3));  // KHOOR
// console.log(caesar.decrypt("KHOOR", 3));  // HELLO
