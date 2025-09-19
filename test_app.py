import unittest
import os
from utils.crypto_handler import CryptoHandler
from utils.qr_code_generator import QRCodeGenerator
from utils.config import QRCodeParameters, QRErrorCorrection

class TestApp(unittest.TestCase):
    def test_encryption_decryption(self):
        # Test data
        data = b"This is a test."
        password = "password"

        # Test encryption
        salt, iv, ciphertext, kdf_version = CryptoHandler.encrypt_data(data, password, kdf_version="argon2")
        self.assertIsNotNone(salt)
        self.assertIsNotNone(iv)
        self.assertIsNotNone(ciphertext)
        self.assertEqual(kdf_version, "argon2")

        # Test decryption
        decrypted_data = CryptoHandler.decrypt_data(ciphertext, salt, iv, password, kdf_version)
        self.assertEqual(data, decrypted_data)

    def test_qr_code_generation(self):
        # Test data
        data = "This is a test."
        params = QRCodeParameters(version=1, error_correction=QRErrorCorrection.LOW.value, box_size=10)

        # Test QR code generation
        img = QRCodeGenerator.create_qr_code(data, params)
        self.assertIsNotNone(img)

if __name__ == "__main__":
    unittest.main()
