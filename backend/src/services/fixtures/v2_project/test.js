const crypto = require('crypto');
// Rule 1: weak-hash-node-crypto (MD5)
const hash = crypto.createHash('md5');
// Rule 2: rsa-weak-keysize-node-crypto (1024)
crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
// SWEET32: 3DES
const legacy = crypto.createCipheriv('des-ede3-cbc', 'key', 'iv');
