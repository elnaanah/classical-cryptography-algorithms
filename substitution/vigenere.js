/**
 * ملف: vigenere.js
 * الوصف: شيفرة فيجنير (Vigenère Cipher) - التشفير متعدد الأبجديات
 * 
 * آلية العمل:
 * - تستخدم كلمة مفتاحية تُكرر لتغطية طول الرسالة
 * - التشفير: C = (P + K[i]) mod 26
 * - فك التشفير: P = (C - K[i]) mod 26
 * 
 * مثال: النص "HELLO" مع المفتاح "KEY"
 * المفتاح المكرر: K-E-Y-K-E
 * كل حرف يُشفر بإزاحة مختلفة حسب حرف المفتاح المقابل
 * 
 * الأمان: أقوى من شيفرة قيصر لأنها تستخدم إزاحات متعددة
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

/**
 * دالة التحقق من صحة المفتاح
 * @param {string} key - الكلمة المفتاحية
 * @returns {string} - المفتاح بعد التصفية (أحرف كبيرة فقط)
 * @throws {Error} - إذا كان المفتاح لا يحتوي على أحرف
 */
function validateKey(key) {
  // استخراج الأحرف فقط وتحويلها لأحرف كبيرة
  const filtered = key.toUpperCase().split('').filter(c => isLetter(c));
  
  if (filtered.length === 0) {
    throw new Error('Key must contain at least one letter');
  }
  
  return filtered.join('');
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - الكلمة المفتاحية
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  const keyUpper = validateKey(key);
  let keyIndex = 0;
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية (لا تستهلك من المفتاح)
    if (!isLetter(char)) return char;
    
    // تحويل الحرف الأصلي إلى رقم
    const p = letterToNum(char);
    
    // الحصول على حرف المفتاح المقابل (مع التكرار الدوري)
    const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
    keyIndex++;
    
    // تطبيق معادلة التشفير: C = (P + K) mod 26
    const c = mod(p + k, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {string} key - الكلمة المفتاحية (نفسها المستخدمة في التشفير)
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  const keyUpper = validateKey(key);
  let keyIndex = 0;
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // تحويل الحرف المشفر إلى رقم
    const c = letterToNum(char);
    
    // الحصول على حرف المفتاح المقابل
    const k = letterToNum(keyUpper[keyIndex % keyUpper.length]);
    keyIndex++;
    
    // تطبيق معادلة فك التشفير: P = (C - K) mod 26
    const p = mod(c - k, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const vigenere = require('./vigenere');
// console.log(vigenere.encrypt("HELLO", "KEY"));  // RIJVS
// console.log(vigenere.decrypt("RIJVS", "KEY"));  // HELLO
