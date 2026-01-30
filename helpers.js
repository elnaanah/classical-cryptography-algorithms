/**
 * ملف: helpers.js
 * الوصف: الدوال المساعدة المشتركة لخوارزميات التشفير الكلاسيكية
 * 
 * يحتوي على:
 * - تحويل الأحرف إلى أرقام والعكس
 * - عمليات الباقي (mod) الرياضية
 * - حساب المعكوس الضربي
 * - فحص الأعداد الأولية المتبادلة
 */

/**
 * تحويل حرف إلى رقم
 * A=0, B=1, C=2, ..., Z=25
 * 
 * @param {string} char - الحرف المراد تحويله
 * @returns {number} - القيمة الرقمية للحرف (0-25)
 * 
 * مثال: letterToNum('A') → 0, letterToNum('Z') → 25
 */
function letterToNum(char) {
  // تحويل الحرف للكود ASCII ثم طرح 65 (كود الحرف A)
  return char.toUpperCase().charCodeAt(0) - 65;
}

/**
 * تحويل رقم إلى حرف
 * 0=A, 1=B, 2=C, ..., 25=Z
 * 
 * @param {number} num - الرقم المراد تحويله
 * @returns {string} - الحرف المقابل (A-Z)
 * 
 * مثال: numToLetter(0) → 'A', numToLetter(25) → 'Z'
 */
function numToLetter(num) {
  // معالجة الأرقام السالبة وخارج النطاق
  // ((num % 26) + 26) % 26 يضمن نتيجة بين 0-25
  return String.fromCharCode(((num % 26) + 26) % 26 + 65);
}

/**
 * التحقق مما إذا كان الحرف أبجدياً (إنجليزي)
 * 
 * @param {string} char - الحرف المراد فحصه
 * @returns {boolean} - true إذا كان حرفاً أبجدياً
 * 
 * مثال: isLetter('A') → true, isLetter('5') → false
 */
function isLetter(char) {
  return /^[A-Za-z]$/.test(char);
}

/**
 * حساب باقي القسمة مع معالجة الأرقام السالبة
 * 
 * في JavaScript، العامل % يُرجع باقياً سالباً للأرقام السالبة
 * مثال: -1 % 26 = -1 (في JS)، لكننا نريد 25
 * 
 * @param {number} n - العدد المقسوم
 * @param {number} m - المقسوم عليه
 * @returns {number} - الباقي الموجب دائماً (0 إلى m-1)
 * 
 * مثال: mod(-1, 26) → 25, mod(27, 26) → 1
 */
function mod(n, m) {
  return ((n % m) + m) % m;
}

/**
 * حساب المعكوس الضربي في نظام mod
 * 
 * المعكوس الضربي لـ a في mod m هو العدد x حيث:
 * (a × x) mod m = 1
 * 
 * يوجد معكوس فقط إذا كان gcd(a, m) = 1 (أي a و m أوليان متبادلان)
 * 
 * @param {number} a - العدد المراد إيجاد معكوسه
 * @param {number} m - المقسوم عليه (modulus)
 * @returns {number|null} - المعكوس الضربي، أو null إذا لم يوجد
 * 
 * مثال: modInverse(5, 26) → 21 (لأن 5 × 21 = 105 = 4×26 + 1)
 */
function modInverse(a, m) {
  a = mod(a, m);
  
  // البحث عن x حيث (a × x) mod m = 1
  // طريقة بسيطة: تجربة جميع القيم من 1 إلى m-1
  for (let x = 1; x < m; x++) {
    if (mod(a * x, m) === 1) return x;
  }
  
  // لا يوجد معكوس (a ليس أولياً مع m)
  return null;
}

/**
 * حساب القاسم المشترك الأكبر (GCD) باستخدام خوارزمية إقليدس
 * 
 * @param {number} a - العدد الأول
 * @param {number} b - العدد الثاني
 * @returns {number} - القاسم المشترك الأكبر
 * 
 * مثال: gcd(12, 8) → 4, gcd(5, 26) → 1
 */
function gcd(a, b) {
  // خوارزمية إقليدس: نستبدل (a, b) بـ (b, a mod b) حتى b = 0
  while (b !== 0) {
    [a, b] = [b, a % b];
  }
  return a;
}

/**
 * التحقق مما إذا كان عددان أوليين متبادلين (Coprime)
 * 
 * عددان أوليان متبادلان إذا كان gcd(a, b) = 1
 * أي لا يوجد عامل مشترك بينهما غير 1
 * 
 * @param {number} a - العدد الأول
 * @param {number} b - العدد الثاني
 * @returns {boolean} - true إذا كانا أوليين متبادلين
 * 
 * مثال: isCoprime(5, 26) → true, isCoprime(4, 26) → false
 * 
 * ملاحظة: هذا مهم في التشفير لأن:
 * - في شيفرة أفين: a يجب أن يكون أولياً مع 26
 * - في شيفرة الضرب: المفتاح يجب أن يكون أولياً مع 26
 * - في شيفرة هيل: محدد المصفوفة يجب أن يكون أولياً مع 26
 */
function isCoprime(a, b) {
  return gcd(a, b) === 1;
}

// تصدير جميع الدوال للاستخدام في الملفات الأخرى
module.exports = { letterToNum, numToLetter, isLetter, mod, modInverse, gcd, isCoprime };
