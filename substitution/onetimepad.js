/**
 * ملف: onetimepad.js
 * الوصف: شيفرة اللوحة لمرة واحدة (One-Time Pad / Vernam Cipher)
 * 
 * آلية العمل:
 * - المفتاح يجب أن يكون بنفس طول النص بالضبط
 * - التشفير: C = (P + K) mod 26
 * - فك التشفير: P = (C - K) mod 26
 * 
 * الأمان:
 * - توفر سرية تامة (Perfect Secrecy) إذا كان المفتاح:
 *   1. عشوائياً تماماً
 *   2. بنفس طول الرسالة
 *   3. يُستخدم مرة واحدة فقط
 * 
 * تحذير: إعادة استخدام المفتاح تُضعف الأمان بشكل كبير!
 */

// استيراد الدوال المساعدة
const { letterToNum, numToLetter, isLetter, mod } = require('../helpers');

/**
 * دالة التحقق من صحة المفتاح
 * @param {string} text - النص (الأصلي أو المشفر)
 * @param {string} key - المفتاح
 * @returns {string} - المفتاح بعد التصفية (أحرف كبيرة فقط)
 * @throws {Error} - إذا كان طول المفتاح لا يساوي طول النص
 */
function validateKey(text, key) {
  // عد الأحرف في النص (بدون الأرقام والرموز)
  const textLetterCount = text.split('').filter(isLetter).length;
  
  // استخراج الأحرف من المفتاح
  const keyLetters = key.split('').filter(isLetter);
  
  // التحقق من تطابق الأطوال
  if (keyLetters.length !== textLetterCount) {
    throw new Error(
      `Key length (${keyLetters.length} letters) must equal text length (${textLetterCount} letters). ` +
      'One-Time Pad requires the key to be exactly as long as the message.'
    );
  }
  
  return keyLetters.map(c => c.toUpperCase()).join('');
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - المفتاح (بنفس طول النص)
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  // التحقق من المفتاح
  const keyUpper = validateKey(plaintext, key);
  let keyIndex = 0;
  
  return plaintext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // الحصول على قيمة الحرف الأصلي وحرف المفتاح المقابل
    const p = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex]);
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
 * @param {string} key - المفتاح (نفس المفتاح المستخدم في التشفير)
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  // التحقق من المفتاح
  const keyUpper = validateKey(ciphertext, key);
  let keyIndex = 0;
  
  return ciphertext.split('').map(char => {
    // تجاهل الأحرف غير الأبجدية
    if (!isLetter(char)) return char;
    
    // الحصول على قيمة الحرف المشفر وحرف المفتاح المقابل
    const c = letterToNum(char);
    const k = letterToNum(keyUpper[keyIndex]);
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
// const otp = require('./onetimepad');
// console.log(otp.encrypt("HELLO", "XMCKL"));  // EQNVZ
// console.log(otp.decrypt("EQNVZ", "XMCKL"));  // HELLO
