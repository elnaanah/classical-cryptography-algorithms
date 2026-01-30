# Classical Cryptography Algorithms (JavaScript)

مشروع تعليمي يهدف إلى **تطبيق ودراسة خوارزميات التشفير الكلاسيكية** باستخدام JavaScript، مع التركيز على:

* الفهم الرياضي للخوارزميات
* التصنيف الأكاديمي الصحيح
* فصل المنطق، التنظيم الجيد، وقابلية الاختبار

> ⚠️ **تنبيه أمني**
> هذا المشروع **تعليمي فقط**. الخوارزميات المطبقة **غير آمنة** للاستخدام في أي نظام حقيقي أو إنتاجي.

---

## 📁 هيكل المشروع

```text
project/
├── helpers.js                    # دوال مساعدة مشتركة (mod, gcd, inverse, etc.)
├── test.js                       # اختبارات تشغيلية للخوارزميات
├── substitution/                 # Substitution Ciphers
│   ├── caesar.js
│   ├── multiplicative.js
│   ├── monoalphabetic.js
│   ├── vigenere.js
│   ├── affine.js
│   ├── playfair.js
│   ├── hill.js
│   ├── autokey.js
│   └── onetimepad.js
└── transposition/                # Transposition Ciphers
    ├── railfence.js
    └── columnar.js
```

### مبادئ التصميم

* كل خوارزمية في ملف مستقل
* واجهة موحدة:

  ```js
  encrypt(plaintext, key)
  decrypt(ciphertext, key)
  ```
* عدم وجود state مشترك
* دعم الأحرف غير الإنجليزية بدون تعديل

---

## 📚 التصنيف الأكاديمي للخوارزميات

### 1️⃣ Substitution Ciphers

تعتمد على **استبدال الحروف** مع الحفاظ على مواقعها.

#### Monoalphabetic Substitution

| Algorithm      | Key Type                  | Formula               | Security  |
| -------------- | ------------------------- | --------------------- | --------- |
| Caesar         | Integer shift             | `C = (P + k) mod 26`  | Very Weak |
| Multiplicative | Integer (coprime with 26) | `C = (P × k) mod 26`  | Weak      |
| Affine         | `(a, b)`                  | `C = (aP + b) mod 26` | Weak      |
| Monoalphabetic | Alphabet permutation      | Lookup table          | Weak      |

#### Polyalphabetic Substitution

| Algorithm    | Key                 | Notes            | Security    |
| ------------ | ------------------- | ---------------- | ----------- |
| Vigenère     | Repeating word      | Periodic key     | Medium      |
| Autokey      | Word + plaintext    | Non-periodic     | Medium+     |
| One-Time Pad | Random, same length | Perfect secrecy* | Theoretical |

> *Perfect secrecy only if the key is truly random, never reused, and equal in length to the message.

#### Polygraphic / Block Ciphers

| Algorithm | Block Size | Key        | Security |
| --------- | ---------- | ---------- | -------- |
| Playfair  | 2 letters  | 5×5 matrix | Medium   |
| Hill      | n letters  | n×n matrix | Medium+  |

---

### 2️⃣ Transposition Ciphers

تعتمد على **إعادة ترتيب المواقع** دون تغيير الحروف.

| Algorithm  | Method            | Key             | Security |
| ---------- | ----------------- | --------------- | -------- |
| Rail Fence | Zigzag pattern    | Number of rails | Weak     |
| Columnar   | Column reordering | Keyword         | Medium   |

---

## 🧪 الخوارزميات المدعومة (مع أمثلة)

### Caesar Cipher

```js
const caesar = require('./substitution/caesar');

caesar.encrypt("HELLO", 3);   // KHOOR
caesar.decrypt("KHOOR", 3);   // HELLO
```

---

### Multiplicative Cipher

```js
const mult = require('./substitution/multiplicative');

mult.encrypt("HELLO", 7);     // XCZZU
mult.decrypt("XCZZU", 7);     // HELLO
```

---

### Monoalphabetic Cipher

```js
const mono = require('./substitution/monoalphabetic');

const key = "QWERTYUIOPASDFGHJKLZXCVBNM";
mono.encrypt("HELLO", key);   // ITSSG
mono.decrypt("ITSSG", key);   // HELLO
```

---

### Vigenère Cipher

```js
const vigenere = require('./substitution/vigenere');

vigenere.encrypt("HELLO", "KEY");  // RIJVS
vigenere.decrypt("RIJVS", "KEY");  // HELLO
```

---

### Affine Cipher

```js
const affine = require('./substitution/affine');

affine.encrypt("HELLO", { a: 5, b: 8 });  // RCLLA
affine.decrypt("RCLLA", { a: 5, b: 8 });  // HELLO
```

---

### Playfair Cipher

```js
const playfair = require('./substitution/playfair');

playfair.encrypt("HELLO", "MONARCHY");  // CFSUPM
playfair.decrypt("CFSUPM", "MONARCHY"); // HELXLO
```

**ملاحظة تقنية:**
إدخال حرف padding (`X`) بين الحروف المتكررة سلوك قياسي في Playfair وليس خطأ برمجيًا.

---

### Hill Cipher

```js
const hill = require('./substitution/hill');

const key = [
  [6, 24, 1],
  [13, 16, 10],
  [20, 17, 15]
];

hill.encrypt("ACT", key);   // POH
hill.decrypt("POH", key);   // ACT
```

---

### Autokey Cipher

```js
const autokey = require('./substitution/autokey');

autokey.encrypt("HELLO", "KEY");  // RIJSS
autokey.decrypt("RIJSS", "KEY");  // HELLO
```

---

### One-Time Pad

```js
const otp = require('./substitution/onetimepad');

otp.encrypt("HELLO", "XMCKL");  // EQNVZ
otp.decrypt("EQNVZ", "XMCKL");  // HELLO
```

---

### Rail Fence Cipher

```js
const railfence = require('./transposition/railfence');

railfence.encrypt("HELLOWORLD", 3);  // HOLELWRDLO
railfence.decrypt("HOLELWRDLO", 3);  // HELLOWORLD
```

---

### Columnar Transposition

```js
const columnar = require('./transposition/columnar');

const encrypted = columnar.encrypt("HELLOWORLD", "ZEBRA");
columnar.decrypt(encrypted, "ZEBRA");
```

---

## ▶️ التشغيل

تشغيل الاختبارات:

```bash
node test.js
```

🌐 واجهة الاستخدام (Web Interface)

يوفّر المشروع واجهة ويب تفاعلية تتيح تجربة جميع خوارزميات التشفير بشكل مباشر دون الحاجة إلى سطر الأوامر.

فتح الموقع

لا يتطلب الموقع أي إعداد أو خادم محلي.
يمكن تشغيله مباشرة عبر المتصفح:

index.html


📌 فقط قم بفتح الملف باستخدام أي متصفح حديث (Chrome، Firefox، Edge).

مميزات الواجهة

صفحة كاملة بتصميم واضح وسهل الاستخدام

تجربة التشفير وفك التشفير مباشرة

اختيار الخوارزمية من قائمة واحدة

إدخال النص والمفتاح بشكل تفاعلي

عرض النتائج فورياً

تعمل بالكامل على المتصفح (Client-Side فقط)

لا تعتمد على أي مكتبات خارجية

الغرض من الواجهة

تهدف الواجهة إلى:

تسهيل الفهم العملي للخوارزميات

ربط المفاهيم النظرية بالتطبيق

استخدامها في الشرح الأكاديمي والعروض التقديمية

تمكين التجربة السريعة دون كتابة كود

⚠️ تنبيه
واجهة الويب، مثل باقي المشروع، مخصصة للأغراض التعليمية فقط ولا يجب استخدامها لأي غرض أمني حقيقي.

---

## 📝 ملاحظات عامة

* يتم الحفاظ على حالة الأحرف (Upper / Lower case)
* الأحرف غير الإنجليزية لا تتأثر
* جميع العمليات تتم باستخدام `mod 26`
* لا توجد أي مكتبات خارجية

---

## 🎯 أهداف تعليمية

* فهم التشفير الكلاسيكي قبل الانتقال إلى Modern Cryptography
* ربط الجانب الرياضي بالتطبيق البرمجي
* تدريب على كتابة كود نظيف وقابل للاختبار