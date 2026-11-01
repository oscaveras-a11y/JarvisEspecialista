"""Versioned exact signatures and API allowlist. No arbitrary specimen text export."""
AES_SBOX=bytes.fromhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d83115304c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc22a908846eeb814de5e0bdb e0323a0a4906245cc2d3ac629195e479 e7c8376d8dd54ea96c56f4ea657aae08 ba78252e1ca6b4c6e8dd741f4bbd8b8a 703eb5664803f60e613557b986c11d9e e1f8981169d98e949b1e87e9ce5528df 8ca1890dbfe6426841992d0fb054bb16')
SHA256_K='428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5 d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174 e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da 983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967 27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85 a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070 19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2'
APIS={
 'BCryptEncrypt':'cryptographic API','BCryptDecrypt':'cryptographic API',
 'BCryptOpenAlgorithmProvider':'cryptographic API','BCryptHashData':'hash API',
 'CryptEncrypt':'cryptographic API','CryptDecrypt':'cryptographic API',
 'CryptCreateHash':'hash API','CryptAcquireContextA':'cryptographic API',
 'CryptAcquireContextW':'cryptographic API',
 'EVP_EncryptInit_ex':'cryptographic API','EVP_DecryptInit_ex':'cryptographic API',
 'EVP_CipherInit_ex':'cryptographic API','EVP_DigestInit_ex':'hash API',
 'AES_encrypt':'AES','AES_decrypt':'AES','SHA256_Init':'SHA-256',
 'SHA256_Update':'SHA-256','SHA256_Final':'SHA-256',
 'crypto_aead_chacha20poly1305_ietf_encrypt':'ChaCha20-Poly1305',
 'sodium_init':'cryptographic library',
}
CONSTANTS=[('aes.sbox.v1','AES',AES_SBOX),
 ('sha256.k.le.v1','SHA-256',b''.join(int(w,16).to_bytes(4,'little') for w in SHA256_K.split())),
 ('sha256.k.be.v1','SHA-256',bytes.fromhex(SHA256_K.replace(' ',''))),
 ('chacha.sigma.v1','ChaCha20',b'expand 32-byte k')]
STRINGS={'AES-256':'AES','AES-128':'AES','SHA-256':'SHA-256',
 'SHA256':'SHA-256','ChaCha20':'ChaCha20','OpenSSL':'cryptographic library',
 **APIS}
INSTRUCTIONS={'aesenc':'AES','aesenclast':'AES','aesdec':'AES','aesdeclast':'AES',
 'aesimc':'AES','aeskeygenassist':'AES','vaesenc':'AES','vaesdec':'AES',
 'aese':'AES','aesd':'AES','aesmc':'AES','sha256h':'SHA-256','sha256h2':'SHA-256',
 'sha256su0':'SHA-256','sha256su1':'SHA-256','sha256rnds2':'SHA-256',
 'sha256msg1':'SHA-256','sha256msg2':'SHA-256'}
