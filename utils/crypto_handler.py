# utils/crypto_handler.py

import base64
import hashlib
from typing import Tuple, Dict
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from argon2.low_level import hash_secret_raw, Type
from .config import SecurityConfig

class CryptoHandler:
    """Handles all cryptographic operations with support for PBKDF2 and Argon2."""
    
    @staticmethod
    def generate_key(password: str, salt: bytes, kdf_version: str = "pbkdf2") -> bytes:
        """Generate a key using either PBKDF2 or Argon2."""
        if len(password) < SecurityConfig.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long")
        
        if kdf_version == "pbkdf2":
            # Use PBKDF2 for backward compatibility
            return PBKDF2(
                password.encode('utf-8'),  # Ensure password is in bytes
                salt,
                dkLen=SecurityConfig.AES_KEY_SIZE,
                count=SecurityConfig.PBKDF2_ITERATIONS,
                hmac_hash_module=hashlib.sha256
            )
        elif kdf_version == "argon2":
            # Use Argon2 for improved security
            return hash_secret_raw(
                secret=password.encode('utf-8'),  # Convert password to bytes
                salt=salt,
                time_cost=2,          # Adjust as needed
                memory_cost=102400,   # Adjust as needed (in KB)
                parallelism=8,        # Adjust as needed
                hash_len=SecurityConfig.AES_KEY_SIZE,
                type=Type.ID
            )
        else:
            raise ValueError("Unsupported KDF version")

    @staticmethod
    def encrypt_data(data: bytes, password: str, kdf_version: str = "pbkdf2") -> Tuple[bytes, bytes, bytes, str]:
        """Encrypt data and include the KDF version in the payload."""
        salt = get_random_bytes(SecurityConfig.SALT_SIZE)
        key = CryptoHandler.generate_key(password, salt, kdf_version)
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = CryptoHandler._pkcs7_pad(data)
        ciphertext = cipher.encrypt(padded_data)
        return salt, cipher.iv, ciphertext, kdf_version

    @staticmethod
    def decrypt_data(encrypted_data: bytes, salt: bytes, iv: bytes, password: str, kdf_version: str) -> bytes:
        """Decrypt data using the specified KDF version."""
        key = CryptoHandler.generate_key(password, salt, kdf_version)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return CryptoHandler._pkcs7_unpad(decrypted_padded)

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        """Pad data using PKCS7."""
        pad_len = SecurityConfig.AES_BLOCK_SIZE - len(data) % SecurityConfig.AES_BLOCK_SIZE
        padding = bytes([pad_len] * pad_len)
        return data + padding

    @staticmethod
    def _pkcs7_unpad(data: bytes) -> bytes:
        """Unpad data using PKCS7."""
        pad_len = data[-1]
        if not (1 <= pad_len <= SecurityConfig.AES_BLOCK_SIZE):
            raise ValueError("Invalid padding length")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid padding")
        return data[:-pad_len]
