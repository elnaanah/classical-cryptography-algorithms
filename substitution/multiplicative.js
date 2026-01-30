/**
 * ملف: multiplicative.js
 * الوصف: شيفرة الضرب (Multiplicative Cipher)
 * 
 * آلية العمل:
 * - التشفير: C = (P × k) mod 26
 * - فك التشفير: P = (C × k⁻¹) mod 26
 * 
 * المفتاح: عدد k يجب أن يكون أولياً مع 26 (ليوجد له معكوس)
 * القيم الصالحة: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
 * 
 * ملاحظة: هذه حالة خاصة من شيفرة أفين حيث b = 0
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod, modInverse, isCoprime } = require('../helpers');

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {number} key - مفتاح الضرب (يجب أن يكون أولياً مع 26)
 * @returns {string} - النص المشفر
 * @throws {Error} - إذا كان المفتاح غير صالح
 */
function encrypt(plaintext, key) {
  // التحقق من أن المفتاح أولي مع 26
  if (!isCoprime(key, 26)) {
    throw new Error(`Key ${key} is not coprime with 26. Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25`);
  }
  
  // تطبيق mod 26 على المفتاح
  const k = mod(key, 26);
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // تحويل الحرف إلى رقم
    const p = letterToNum(char);
    
    // تطبيق معادلة التشفير: C = (P × k) mod 26
    const c = mod(p * k, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {number} key - مفتاح الضرب
 * @returns {string} - النص الأصلي
 * @throws {Error} - إذا كان المفتاح غير صالح
 */
function decrypt(ciphertext, key) {
  // التحقق من صحة المفتاح
  if (!isCoprime(key, 26)) {
    throw new Error(`Key ${key} is not coprime with 26. Valid keys: 1,3,5,7,9,11,15,17,19,21,23,25`);
  }
  
  const k = mod(key, 26);
  
  // حساب المعكوس الضربي للمفتاح
  // k × k⁻¹ ≡ 1 (mod 26)
  const kInv = modInverse(k, 26);
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // تحويل الحرف المشفر إلى رقم
    const c = letterToNum(char);
    
    // تطبيق معادلة فك التشفير: P = (C × k⁻¹) mod 26
    const p = mod(c * kInv, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const mult = require('./multiplicative');
// console.log(mult.encrypt("HELLO", 7));  // XCZZU
// console.log(mult.decrypt("XCZZU", 7));  // HELLO
