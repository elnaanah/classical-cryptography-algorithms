/**
 * ملف: monoalphabetic.js
 * الوصف: شيفرة الاستبدال الأحادي (Monoalphabetic Substitution Cipher)
 * 
 * آلية العمل:
 * - تستخدم تبديلاً ثابتاً للأبجدية كمفتاح
 * - كل حرف في النص الأصلي يُستبدل بحرف واحد محدد ثابت
 * 
 * المفتاح: سلسلة من 26 حرفاً تمثل الأبجدية المبدلة
 * مثال: إذا كان المفتاح "QWERTYUIOPASDFGHJKLZXCVBNM"
 * فإن A ← Q، B ← W، C ← E، وهكذا
 */

// استيراد الدوال المساعدة
const { isLetter } = require('../helpers');

// الأبجدية الأصلية
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/**
 * دالة التحقق من صحة المفتاح
 * @param {string} key - المفتاح (تبديل الأبجدية)
 * @returns {string} - المفتاح بالأحرف الكبيرة
 * @throws {Error} - إذا كان المفتاح غير صالح
 */
function validateKey(key) {
  const upper = key.toUpperCase();
  
  // يجب أن يكون المفتاح 26 حرفاً بالضبط
  if (upper.length !== 26) {
    throw new Error('Key must be exactly 26 characters');
  }
  
  // يجب أن يحتوي على كل حرف من الأبجدية مرة واحدة بالضبط
  const sorted = upper.split('').sort().join('');
  if (sorted !== ALPHABET) {
    throw new Error('Key must be a permutation of the alphabet (each letter exactly once)');
  }
  
  return upper;
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - مفتاح التبديل (26 حرفاً)
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  const keyUpper = validateKey(key);
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // إيجاد موقع الحرف في الأبجدية الأصلية
    const index = ALPHABET.indexOf(char.toUpperCase());
    
    // استبداله بالحرف المقابل في المفتاح
    const encrypted = keyUpper[index];
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? encrypted : encrypted.toLowerCase();
  }).join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {string} key - مفتاح التبديل
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  const keyUpper = validateKey(key);
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // إيجاد موقع الحرف المشفر في المفتاح
    const index = keyUpper.indexOf(char.toUpperCase());
    
    // استبداله بالحرف المقابل في الأبجدية الأصلية
    const decrypted = ALPHABET[index];
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? decrypted : decrypted.toLowerCase();
  }).join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const mono = require('./monoalphabetic');
// const key = 'QWERTYUIOPASDFGHJKLZXCVBNM';
// console.log(mono.encrypt("HELLO", key));  // ITSSG
// console.log(mono.decrypt("ITSSG", key));  // HELLO
