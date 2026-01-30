/**
 * ملف: railfence.js
 * الوصف: شيفرة السياج (Rail Fence Cipher) - تشفير التبديل
 * 
 * آلية العمل:
 * - التشفير: كتابة النص بشكل متعرج (زيجزاج) عبر N سكك (صفوف)، ثم القراءة أفقياً
 * - فك التشفير: عكس العملية
 * 
 * مثال: النص "HELLOWORLD" مع 3 سكك:
 * 
 *   سكة 0: H . . . O . . . L .
 *   سكة 1: . E . L . W . R . D
 *   سكة 2: . . L . . . O . . .
 * 
 * القراءة: HOL + ELWRD + LO = "HOLELWRDLO"
 * 
 * الاتجاه: نبدأ من الأعلى، ننزل حتى آخر سكة، ثم نصعد، وهكذا (زيجزاج)
 */

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {number} numRails - عدد السكك (يجب أن يكون 2 على الأقل)
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, numRails) {
  // التحقق من صحة عدد السكك
  if (numRails < 2) throw new Error('Number of rails must be at least 2');
  if (plaintext.length === 0) return '';
  
  // إنشاء مصفوفة السكك (كل سكة = صف)
  const rails = Array.from({ length: numRails }, () => []);
  
  let rail = 0;      // السكة الحالية (نبدأ من الأعلى)
  let direction = 1; // الاتجاه: 1 = نزول، -1 = صعود
  
  // توزيع الأحرف بنمط الزيجزاج
  for (const char of plaintext) {
    // إضافة الحرف للسكة الحالية
    rails[rail].push(char);
    
    // الانتقال للسكة التالية
    rail += direction;
    
    // عكس الاتجاه عند الوصول للسكة العليا أو السفلى
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  // القراءة الأفقية: دمج جميع السكك
  return rails.flat().join('');
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {number} numRails - عدد السكك
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, numRails) {
  // التحقق من صحة المدخلات
  if (numRails < 2) throw new Error('Number of rails must be at least 2');
  if (ciphertext.length === 0) return '';
  
  const len = ciphertext.length;
  
  // الخطوة 1: حساب عدد الأحرف في كل سكة
  // نحاكي عملية التشفير لمعرفة كم حرفاً يذهب لكل سكة
  const railLengths = Array(numRails).fill(0);
  let rail = 0;
  let direction = 1;
  
  for (let i = 0; i < len; i++) {
    railLengths[rail]++;  // زيادة عداد السكة الحالية
    rail += direction;
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  // الخطوة 2: تقسيم النص المشفر إلى سكك
  // كل سكة تأخذ عدد الأحرف المحسوب لها
  const rails = [];
  let index = 0;
  
  for (let r = 0; r < numRails; r++) {
    rails.push(ciphertext.slice(index, index + railLengths[r]).split(''));
    index += railLengths[r];
  }
  
  // الخطوة 3: إعادة بناء النص بقراءة الزيجزاج
  // نتبع نفس نمط التشفير، لكن نأخذ حرفاً من كل سكة بالترتيب
  const result = [];
  rail = 0;
  direction = 1;
  
  for (let i = 0; i < len; i++) {
    // أخذ الحرف الأول من السكة الحالية
    result.push(rails[rail].shift());
    
    // الانتقال للسكة التالية
    rail += direction;
    if (rail === 0 || rail === numRails - 1) {
      direction = -direction;
    }
  }
  
  return result.join('');
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const railfence = require('./railfence');
// console.log(railfence.encrypt("HELLOWORLD", 3));  // HOLELWRDLO
// console.log(railfence.decrypt("HOLELWRDLO", 3));  // HELLOWORLD
