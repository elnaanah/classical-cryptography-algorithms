/**
 * ملف: columnar.js
 * الوصف: شيفرة التبديل العمودي (Columnar Transposition Cipher)
 * 
 * آلية العمل:
 * - التشفير: كتابة النص في صفوف (أفقياً)، ثم قراءة الأعمدة بترتيب أبجدي حسب المفتاح
 * - فك التشفير: عكس العملية - ملء الأعمدة ثم قراءة الصفوف
 * 
 * مثال: النص "HELLOWORLD" مع المفتاح "ZEBRA"
 * ترتيب الأعمدة حسب ZEBRA: Z(5) E(2) B(1) R(4) A(0) → القراءة: A, B, E, R, Z
 * 
 * الشبكة:
 *   Z E B R A
 *   H E L L O
 *   W O R L D
 * 
 * القراءة بترتيب الأعمدة: OD + LR + EO + LL + HW = "ODLREOLLHW"
 */

/**
 * الحصول على ترتيب الأعمدة بناءً على الترتيب الأبجدي للمفتاح
 * @param {string} key - المفتاح
 * @returns {number[]} - مصفوفة تحدد ترتيب قراءة الأعمدة
 * 
 * مثال: المفتاح "ZEBRA"
 * Z=25, E=4, B=1, R=17, A=0 (قيم أبجدية)
 * الترتيب: A(4), B(2), E(1), R(3), Z(0) → [4, 2, 1, 3, 0]
 */
function getColumnOrder(key) {
  const keyUpper = key.toUpperCase();
  
  // إنشاء قائمة من الأحرف مع أرقام مواقعها الأصلية
  const indexed = keyUpper.split('').map((char, i) => ({ char, i }));
  
  // ترتيب أبجدي، وعند التساوي نحافظ على الترتيب الأصلي
  indexed.sort((a, b) => {
    if (a.char !== b.char) return a.char.localeCompare(b.char);
    return a.i - b.i;  // الحرف الذي يظهر أولاً يبقى أولاً
  });
  
  // إرجاع أرقام الأعمدة الأصلية بالترتيب الجديد
  return indexed.map(item => item.i);
}

/**
 * دالة التشفير
 * @param {string} plaintext - النص الأصلي
 * @param {string} key - المفتاح (يحدد عدد الأعمدة وترتيب القراءة)
 * @returns {string} - النص المشفر
 */
function encrypt(plaintext, key) {
  if (!key || key.length === 0) throw new Error('Key must not be empty');
  
  const numCols = key.length;  // عدد الأعمدة = طول المفتاح
  const order = getColumnOrder(key);  // ترتيب قراءة الأعمدة
  
  // بناء الشبكة صفاً تلو الآخر
  // كل صف يحتوي على numCols حرف
  const grid = [];
  for (let i = 0; i < plaintext.length; i += numCols) {
    grid.push(plaintext.slice(i, i + numCols).split(''));
  }
  
  // حشو الصف الأخير إذا كان ناقصاً
  if (grid.length > 0) {
    const lastRow = grid[grid.length - 1];
    while (lastRow.length < numCols) {
      lastRow.push('');  // خانات فارغة
    }
  }
  
  // قراءة الأعمدة بالترتيب المحدد من المفتاح
  let result = '';
  for (const col of order) {
    for (const row of grid) {
      if (row[col]) result += row[col];
    }
  }
  
  return result;
}

/**
 * دالة فك التشفير
 * @param {string} ciphertext - النص المشفر
 * @param {string} key - المفتاح
 * @returns {string} - النص الأصلي
 */
function decrypt(ciphertext, key) {
  if (!key || key.length === 0) throw new Error('Key must not be empty');
  if (ciphertext.length === 0) return '';
  
  const numCols = key.length;
  const numRows = Math.ceil(ciphertext.length / numCols);  // عدد الصفوف
  const order = getColumnOrder(key);
  
  // حساب عدد الخانات الممتلئة في الصف الأخير
  // هذا مهم لأن بعض الأعمدة قد تكون أقصر من غيرها
  const filledInLastRow = ciphertext.length % numCols || numCols;
  
  // تحديد الأعمدة الطويلة (التي تُقرأ أولاً في ترتيب المفتاح)
  // الأعمدة الأولى في ترتيب القراءة تكون كاملة الطول
  const longColumns = new Set();
  for (let i = 0; i < filledInLastRow; i++) {
    longColumns.add(order[i]);
  }
  
  // توزيع النص المشفر على الأعمدة حسب ترتيب القراءة
  const columns = Array.from({ length: numCols }, () => []);
  let index = 0;
  
  for (let i = 0; i < numCols; i++) {
    const originalCol = order[i];  // العمود الأصلي في هذا الموقع من الترتيب
    
    // طول العمود: كامل إذا كان من الأعمدة الطويلة، وإلا أقل بواحد
    const colLength = longColumns.has(originalCol) ? numRows : numRows - 1;
    
    // استخراج أحرف هذا العمود من النص المشفر
    columns[originalCol] = ciphertext.slice(index, index + colLength).split('');
    index += colLength;
  }
  
  // قراءة الشبكة صفاً تلو الآخر (بالترتيب الأصلي للأعمدة)
  let result = '';
  for (let r = 0; r < numRows; r++) {
    for (let c = 0; c < numCols; c++) {
      if (columns[c][r] !== undefined) {
        result += columns[c][r];
      }
    }
  }
  
  return result;
}

// تصدير الدوال
module.exports = { encrypt, decrypt };

// مثال على الاستخدام:
// const columnar = require('./columnar');
// console.log(columnar.encrypt("HELLOWORLD", "ZEBRA"));
// console.log(columnar.decrypt(columnar.encrypt("HELLOWORLD", "ZEBRA"), "ZEBRA"));
