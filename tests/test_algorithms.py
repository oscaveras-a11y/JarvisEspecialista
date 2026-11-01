import unittest

from cyber_core.cryptanalysis.algorithms import (
    demonstrate_rsa_oaep, demonstrate_ecdh_aesgcm, demonstrate_chacha20_poly1305, demonstrate_all,
)


class AlgorithmDemonstrationTests(unittest.TestCase):
    """Item 7: the scope names AES, RSA, ECC and ChaCha20. AES-256-GCM is already
    real (CCAES1); these prove real round-trips for the remaining three, with
    fresh keys generated here — never applied to third-party data."""

    def test_rsa_oaep_round_trips(self):
        out = demonstrate_rsa_oaep()
        self.assertTrue(out['round_trip_ok'])
        self.assertEqual(out['key_size_bits'], 2048)

    def test_ecdh_aesgcm_round_trips_and_agrees(self):
        out = demonstrate_ecdh_aesgcm()
        self.assertTrue(out['round_trip_ok'])
        self.assertTrue(out['shared_secret_agreement_ok'])

    def test_chacha20_poly1305_round_trips(self):
        out = demonstrate_chacha20_poly1305()
        self.assertTrue(out['round_trip_ok'])

    def test_demonstrate_all_covers_three_algorithms(self):
        out = demonstrate_all()
        self.assertTrue(out['rsa_oaep']['round_trip_ok'])
        self.assertTrue(out['ecdh_aesgcm']['round_trip_ok'])
        self.assertTrue(out['chacha20_poly1305']['round_trip_ok'])

    def test_tampered_ciphertext_is_rejected_not_silently_wrong(self):
        # A genuine round-trip demonstration must also show AEAD authentication
        # actually rejects tampering, not just that the happy path works.
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = ChaCha20Poly1305.generate_key()
        import os
        nonce = os.urandom(12)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, b'message', None)
        tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            ChaCha20Poly1305(key).decrypt(nonce, tampered, None)


if __name__ == '__main__':
    unittest.main()
