"""Synthetic round-trip demonstrations of RSA-OAEP, ECDH (X25519)+AES-GCM and
ChaCha20-Poly1305 — the algorithms named in item 7 besides the already-real
AES-256-GCM (CCAES1 envelope). Not a recovery or attack tool: each function
generates its OWN ephemeral key material right here and proves only that a
real encrypt-then-decrypt round-trips correctly with the `cryptography`
library's actual primitives. No key is derived from, or applied to, any
third-party or evidence-derived data.
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LIMIT_OWN_KEY = 'Chave efêmera própria gerada agora; esta demonstração nunca recupera nem ataca material de terceiros.'


def demonstrate_rsa_oaep(message=b'cyber-core synthetic RSA-OAEP round trip'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ciphertext = key.public_key().encrypt(message, oaep)
    plaintext = key.decrypt(ciphertext, oaep)
    return {'algorithm': 'RSA-2048-OAEP-SHA256', 'round_trip_ok': plaintext == message,
            'ciphertext_size': len(ciphertext), 'key_size_bits': key.key_size, 'limitations': _LIMIT_OWN_KEY}


def demonstrate_ecdh_aesgcm(message=b'cyber-core synthetic ECDH+AES-GCM round trip'):
    alice, bob = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    shared_alice = alice.exchange(bob.public_key())
    shared_bob = bob.exchange(alice.public_key())
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'cyber-core-ecdh-demo').derive(shared_alice)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, message, None)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return {'algorithm': 'X25519-ECDH+HKDF-SHA256+AES-256-GCM', 'round_trip_ok': plaintext == message,
            'shared_secret_agreement_ok': shared_alice == shared_bob, 'ciphertext_size': len(ciphertext),
            'limitations': _LIMIT_OWN_KEY}


def demonstrate_chacha20_poly1305(message=b'cyber-core synthetic ChaCha20-Poly1305 round trip'):
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, message, None)
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    return {'algorithm': 'ChaCha20-Poly1305', 'round_trip_ok': plaintext == message,
            'ciphertext_size': len(ciphertext), 'limitations': _LIMIT_OWN_KEY}


def demonstrate_all():
    return {'rsa_oaep': demonstrate_rsa_oaep(), 'ecdh_aesgcm': demonstrate_ecdh_aesgcm(),
            'chacha20_poly1305': demonstrate_chacha20_poly1305(),
            'note': 'Demonstrações sintéticas de competência real com os algoritmos do escopo; não são recuperação nem ataque a dados de terceiros.'}
