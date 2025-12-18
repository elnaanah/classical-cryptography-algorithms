// Test all cipher implementations

const caesar = require('./substitution/caesar');
const multiplicative = require('./substitution/multiplicative');
const monoalphabetic = require('./substitution/monoalphabetic');
const vigenere = require('./substitution/vigenere');
const railfence = require('./transposition/railfence');
const columnar = require('./transposition/columnar');

console.log('=== Caesar Cipher ===');
console.log('Encrypt "HELLO" with key 3:', caesar.encrypt('HELLO', 3));
console.log('Decrypt "KHOOR" with key 3:', caesar.decrypt('KHOOR', 3));

console.log('\n=== Multiplicative Cipher ===');
console.log('Encrypt "HELLO" with key 7:', multiplicative.encrypt('HELLO', 7));
console.log('Decrypt result:', multiplicative.decrypt(multiplicative.encrypt('HELLO', 7), 7));

console.log('\n=== Monoalphabetic Cipher ===');
const monoKey = 'QWERTYUIOPASDFGHJKLZXCVBNM';
console.log('Encrypt "HELLO" with key:', monoalphabetic.encrypt('HELLO', monoKey));
console.log('Decrypt result:', monoalphabetic.decrypt(monoalphabetic.encrypt('HELLO', monoKey), monoKey));

console.log('\n=== Vigenère Cipher ===');
console.log('Encrypt "HELLO" with key "KEY":', vigenere.encrypt('HELLO', 'KEY'));
console.log('Decrypt result:', vigenere.decrypt(vigenere.encrypt('HELLO', 'KEY'), 'KEY'));

console.log('\n=== Rail Fence Cipher ===');
console.log('Encrypt "HELLOWORLD" with 3 rails:', railfence.encrypt('HELLOWORLD', 3));
console.log('Decrypt result:', railfence.decrypt(railfence.encrypt('HELLOWORLD', 3), 3));

console.log('\n=== Columnar Transposition Cipher ===');
console.log('Encrypt "HELLOWORLD" with key "ZEBRA":', columnar.encrypt('HELLOWORLD', 'ZEBRA'));
console.log('Decrypt result:', columnar.decrypt(columnar.encrypt('HELLOWORLD', 'ZEBRA'), 'ZEBRA'));

