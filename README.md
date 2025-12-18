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
│   └── vigenere.js               # شيفرة فيجنير
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

### 5. شيفرة السياج (Rail Fence Cipher)
- كتابة النص قطرياً على عدة سطور ثم القراءة أفقياً

```javascript
const railfence = require('./transposition/railfence');
railfence.encrypt("HELLOWORLD", 3);  // HOLELWRDLO
railfence.decrypt("HOLELWRDLO", 3);  // HELLOWORLD
```

### 6. التبديل العمودي (Columnar Transposition)
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

