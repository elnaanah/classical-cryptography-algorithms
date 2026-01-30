/**
 * ملف: autokey.js
 * الوصف: شيفرة المفتاح التلقائي (Autokey Cipher)
 * 
 * آلية العمل:
 * - المفتاح يبدأ بكلمة مفتاحية، ثم يُستكمل بأحرف النص الأصلي نفسه
 * - التشفير: C = (P + K) mod 26
 * - فك التشفير: P = (C - K) mod 26، حيث يُبنى المفتاح تدريجياً
 * 
 * مثال: النص "HELLO" مع المفتاح "KEY"
 * المفتاح الكامل للتشفير: K-E-Y-H-E (المفتاح + أحرف النص)
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

/**
 * دالة التحقق من صحة المفتاح
 * @param {string} key - الكلمة المفتاحية الأولية
 * @returns {string} - المفتاح بعد التصفية (أحرف كبيرة فقط)
 * @throws {Error} - إذا كان المفتاح لا يحتوي على أحرف
 */
function validateKey(key) {
  // استخراج الأحرف فقط وتحويلها لأحرف كبيرة
  const filtered = key.toUpperCase().split('').filter(isLetter);
  
  if (filtered.length === 0) {
    throw new Error('Key must contain at least one letter');
  }
  
  return filtered.join('');
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - الكلمة المفتاحية الأولية
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  const initialKey = validateKey(key);
  
  // بناء المفتاح الكامل: المفتاح الأولي + أحرف النص الأصلي
  // هذه هي الميزة الفريدة لشيفرة Autokey
  const plaintextLetters = plaintext.split('').filter(isLetter).map(c => c.toUpperCase());
  const fullKey = initialKey + plaintextLetters.join('');
  
  let keyIndex = 0;
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // الحصول على قيمة الحرف الأصلي وحرف المفتاح
    const p = letterToNum(char);
    const k = letterToNum(fullKey[keyIndex]);
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
 * @param {string} key - الكلمة المفتاحية الأولية
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  const initialKey = validateKey(key);
  
  // تيار المفتاح: يبدأ بالمفتاح الأولي، ثم نضيف الأحرف المفككة
  // نبني المفتاح تدريجياً أثناء فك التشفير
  let keyStream = initialKey.split('');
  let keyIndex = 0;
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // الحصول على قيمة الحرف المشفر وحرف المفتاح
    const c = letterToNum(char);
    const k = letterToNum(keyStream[keyIndex]);
    
    // تطبيق معادلة فك التشفير: P = (C - K) mod 26
    const p = mod(c - k, 26);
    
    // إضافة الحرف المفكك إلى تيار المفتاح للاستخدام اللاحق
    // هذا هو "المفتاح التلقائي" - الأحرف المفككة تصبح جزءاً من المفتاح
    keyStream.push(numToLetter(p));
    keyIndex++;
    
    // الحفاظ على حالة الحرف
    return char === char.toUpperCase() ? numToLetter(p) : numToLetter(p).toLowerCase();
  }).join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const autokey = require('./autokey');
// console.log(autokey.encrypt("HELLO", "KEY"));  // المفتاح يصبح K-E-Y-H-E...
// console.log(autokey.decrypt(autokey.encrypt("HELLO", "KEY"), "KEY"));  // HELLO
