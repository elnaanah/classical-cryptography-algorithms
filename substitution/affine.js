/**
 * ملف: affine.js
 * الوصف: شيفرة أفين (التشفير التآلفي)
 * 
 * آلية العمل:
 * - التشفير: C = (a × P + b) mod 26
 * - فك التشفير: P = a⁻¹ × (C - b) mod 26
 * 
 * المفتاح: { a, b } حيث:
 * - a: معامل الضرب (يجب أن يكون أولياً مع 26)
 * - b: معامل الإزاحة
 * 
 * القيم الصالحة لـ a: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
 * (أي الأعداد التي gcd(a, 26) = 1)
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod, modInverse, isCoprime } = require('../helpers');

/**
 * دالة التحقق من صحة المفتاح
 * @param {Object} key - كائن يحتوي على المعاملين a و b
 * @returns {Object} - المفتاح بعد التطبيع (mod 26)
 * @throws {Error} - إذا كان المفتاح غير صالح
 */
function validateKey(key) {
  // التحقق من أن المفتاح كائن صالح
  if (typeof key !== 'object' || key === null) {
    throw new Error('Key must be an object with properties a and b');
  }
  
  // التحقق من أن a و b أرقام
  if (typeof key.a !== 'number' || typeof key.b !== 'number') {
    throw new Error('Key properties a and b must be numbers');
  }
  
  // التحقق من أن a أولي مع 26 (شرط أساسي لوجود معكوس)
  if (!isCoprime(key.a, 26)) {
    throw new Error('Key "a" must be coprime with 26 (gcd(a, 26) = 1). Valid values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25');
  }
  
  // إرجاع المفتاح بعد تطبيق mod 26
  return { a: mod(key.a, 26), b: mod(key.b, 26) };
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {Object} key - المفتاح {a, b}
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  // التحقق من المفتاح واستخراج a و b
  const { a, b } = validateKey(key);
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // تحويل الحرف إلى رقم
    const p = letterToNum(char);
    
    // تطبيق معادلة التشفير: C = (a × P + b) mod 26
    const c = mod(a * p + b, 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(c) : numToLetter(c).toLowerCase();
  }).join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {Object} key - المفتاح {a, b}
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  // التحقق من المفتاح
  const { a, b } = validateKey(key);
  
  // حساب المعكوس الضربي لـ a في mod 26
  // هذا ضروري لعكس عملية الضرب
  const aInverse = modInverse(a, 26);
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // تحويل الحرف المشفر إلى رقم
    const c = letterToNum(char);
    
    // تطبيق معادلة فك التشفير: P = a⁻¹ × (C - b) mod 26
    const p = mod(aInverse * (c - b), 26);
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const affine = require('./affine');
// console.log(affine.encrypt("HELLO", { a: 5, b: 8 }));  // RCLLA
// console.log(affine.decrypt("RCLLA", { a: 5, b: 8 }));  // HELLO
