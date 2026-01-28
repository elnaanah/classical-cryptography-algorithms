# Classical Cryptography Algorithms

مشروع تعليمي لتطبيق خوارزميات التشفير الكلاسيكية باستخدام JavaScript.

## هيكل المشروع

```
project/
├── helpers.js                    # دوال مساعدة مشتركة
├── test.js                       # ملف الاختبار
├── substitution/                 # خوارزميات الاستبدال
│   ├── caesar.js                 # شيفرة قيصر
│   ├── multiplicative.js         # الشيفرة الضربية
│   ├── monoalphabetic.js         # الاستبدال الأحادي
│   ├── vigenere.js               # شيفرة فيجنير
│   ├── affine.js                 # الشيفرة التآلفية
│   ├── playfair.js               # شيفرة بلايفير
│   ├── hill.js                   # شيفرة هيل
│   ├── autokey.js                # شيفرة المفتاح التلقائي
│   └── onetimepad.js             # لوحة المرة الواحدة
└── transposition/                # خوارزميات التبديل
    ├── railfence.js              # شيفرة السياج
    └── columnar.js               # التبديل العمودي
```

## الخوارزميات

### 1. شيفرة قيصر (Caesar Cipher)
- **التشفير**: `C = (P + k) mod 26`
- **فك التشفير**: `P = (C - k) mod 26`
- **المفتاح**: عدد صحيح من 0 إلى 25

```javascript
const caesar = require('./substitution/caesar');
caesar.encrypt("HELLO", 3);  // KHOOR
caesar.decrypt("KHOOR", 3);  // HELLO
```

### 2. الشيفرة الضربية (Multiplicative Cipher)
- **التشفير**: `C = (P × k) mod 26`
- **فك التشفير**: `P = (C × k⁻¹) mod 26`
- **المفتاح**: عدد أولي نسبياً مع 26 (مثل: 1,3,5,7,9,11,15,17,19,21,23,25)

```javascript
const mult = require('./substitution/multiplicative');
mult.encrypt("HELLO", 7);  // XCZZU
mult.decrypt("XCZZU", 7);  // HELLO
```

### 3. الاستبدال الأحادي (Monoalphabetic Cipher)
- **المفتاح**: تبديل كامل للأبجدية (26 حرف)

```javascript
const mono = require('./substitution/monoalphabetic');
const key = 'QWERTYUIOPASDFGHJKLZXCVBNM';
mono.encrypt("HELLO", key);  // ITSSG
mono.decrypt("ITSSG", key);  // HELLO
```

### 4. شيفرة فيجنير (Vigenère Cipher)
- **التشفير**: `C = (P + K[i]) mod 26`
- **فك التشفير**: `P = (C - K[i]) mod 26`
- **المفتاح**: كلمة تتكرر بطول الرسالة

```javascript
const vigenere = require('./substitution/vigenere');
vigenere.encrypt("HELLO", "KEY");  // RIJVS
vigenere.decrypt("RIJVS", "KEY");  // HELLO
```

### 5. الشيفرة التآلفية (Affine Cipher)
- **التشفير**: `C = (aP + b) mod 26`
- **فك التشفير**: `P = a⁻¹(C - b) mod 26`
- **المفتاح**: كائن `{a, b}` حيث `gcd(a, 26) = 1`

```javascript
const affine = require('./substitution/affine');
affine.encrypt("HELLO", { a: 5, b: 8 });  // RCLLA
affine.decrypt("RCLLA", { a: 5, b: 8 });  // HELLO
```

### 6. شيفرة بلايفير (Playfair Cipher)
- **المفتاح**: كلمة تُستخدم لبناء مصفوفة 5×5
- **القواعد**: نفس الصف (إزاحة يمين)، نفس العمود (إزاحة أسفل)، مستطيل (تبديل الأعمدة)

```javascript
const playfair = require('./substitution/playfair');
playfair.encrypt("HELLO", "MONARCHY");  // CFSUPM
playfair.decrypt("CFSUPM", "MONARCHY"); // HELXLO
```

> **ملاحظة حول Padding:** شيفرة Playfair تعالج النص كأزواج من الحروف (digraphs). عند وجود حرفين متتاليين متماثلين (مثل `LL` في `HELLO`)، يُدخل الحرف `X` بينهما ليصبح `LX` و `LO`. لذلك عند فك التشفير يظهر `HELXLO` بدلاً من `HELLO`. هذا سلوك قياسي للخوارزمية وليس خطأ - إزالة حروف الـ padding تتطلب معالجة إضافية خارج نطاق الخوارزمية الأساسية.

### 7. شيفرة هيل (Hill Cipher)
- **التشفير**: `C = K × P mod 26` (ضرب مصفوفات)
- **فك التشفير**: `P = K⁻¹ × C mod 26`
- **المفتاح**: مصفوفة مربعة (2×2 أو 3×3) قابلة للعكس mod 26

```javascript
const hill = require('./substitution/hill');
const key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]];
hill.encrypt("ACT", key);  // POH
hill.decrypt("POH", key);  // ACT
```

### 8. شيفرة المفتاح التلقائي (Autokey Cipher)
- **التشفير**: `C = (P + K) mod 26`
- **المفتاح**: يبدأ بكلمة ثم يُستكمل من النص الصريح

```javascript
const autokey = require('./substitution/autokey');
autokey.encrypt("HELLO", "KEY");  // RIJSS
autokey.decrypt("RIJSS", "KEY");  // HELLO
```

### 9. لوحة المرة الواحدة (One-Time Pad)
- **التشفير**: `C = (P + K) mod 26`
- **المفتاح**: بطول النص تماماً (يرفض التنفيذ إذا اختلف الطول)

```javascript
const otp = require('./substitution/onetimepad');
otp.encrypt("HELLO", "XMCKL");  // EQNVZ
otp.decrypt("EQNVZ", "XMCKL");  // HELLO
```

### 10. شيفرة السياج (Rail Fence Cipher)
- كتابة النص قطرياً على عدة سطور ثم القراءة أفقياً

```javascript
const railfence = require('./transposition/railfence');
railfence.encrypt("HELLOWORLD", 3);  // HOLELWRDLO
railfence.decrypt("HOLELWRDLO", 3);  // HELLOWORLD
```

### 11. التبديل العمودي (Columnar Transposition)
- كتابة النص في جدول وقراءة الأعمدة حسب ترتيب المفتاح أبجدياً

```javascript
const columnar = require('./transposition/columnar');
columnar.encrypt("HELLOWORLD", "ZEBRA");
columnar.decrypt(encrypted, "ZEBRA");
```

## التشغيل

```bash
node test.js
```

## ملاحظات
- الأحرف غير الإنجليزية تبقى كما هي
- يتم الحفاظ على حالة الأحرف (كبيرة/صغيرة)
- جميع العمليات الحسابية تتم بنظام mod 26

