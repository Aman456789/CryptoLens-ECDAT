const crypto = require('crypto');
crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const legacy = crypto.createCipheriv('des-ede3-cbc', key, iv);
