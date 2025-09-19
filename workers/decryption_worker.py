# workers/decryption_worker.py

import logging
import json
import base64
import hashlib
from typing import Optional
from PyQt5.QtCore import QObject, pyqtSignal, QRunnable
from PIL import Image
from pyzbar.pyzbar import decode

from utils.crypto_handler import CryptoHandler
from utils.config import SecurityConfig

class DecryptionWorkerSignals(QObject):
    """Signals for the DecryptionWorker."""
    finished = pyqtSignal()
    success = pyqtSignal(bytes)
    error = pyqtSignal(str)

class DecryptionWorker(QRunnable):
    """Worker for handling decryption in a separate thread."""

    def __init__(self, qr_path: str, password: str, signals: DecryptionWorkerSignals):
        super().__init__()
        self.qr_path = qr_path
        self.password = password
        self.signals = signals

    def run(self) -> None:
        """Execute the decryption task."""
        try:
            # Read and decode QR code
            qr_content = self._read_qr_code()
            if not qr_content:
                return

            # Process and decrypt data
            self._process_and_decrypt(qr_content)

        except Exception as e:
            logging.error(f"Error in decryption worker: {e}")
            self.signals.error.emit(f"An unexpected error occurred: {str(e)}")
        finally:
            self.signals.finished.emit()

    def _read_qr_code(self) -> Optional[str]:
        """Read and decode the QR code from an image file."""
        try:
            # Check if the qr_path is a file path or raw data
            if "\n" in self.qr_path or "{" in self.qr_path:
                return self.qr_path
            else:
                img = Image.open(self.qr_path)
                decoded_objects = decode(img)

                if not decoded_objects:
                    self.signals.error.emit("No QR code found in the image.")
                    return None

                return decoded_objects[0].data.decode('utf-8')
        except Exception as e:
            self.signals.error.emit(f"Failed to read QR code: {str(e)}")
            return None


    def _process_and_decrypt(self, qr_content: str) -> None:
        """Process the QR code content and decrypt it."""
        try:
            content = json.loads(qr_content)
            b64_encoded = content.get("data")
            sha256_hash = content.get("hash")
            kdf_version = content.get("kdf_version", "pbkdf2")

            if not b64_encoded or not sha256_hash:
                self.signals.error.emit("QR code does not contain valid data.")
                return

            # Verify hash
            is_old_qr = 'kdf_version' not in content
            if not self._verify_hash(b64_encoded, sha256_hash, is_old_qr):
                return

            # Decrypt data
            decrypted_data = self._decrypt_data(b64_encoded, kdf_version)
            if decrypted_data:
                self.signals.success.emit(decrypted_data)

        except json.JSONDecodeError:
            self.signals.error.emit("QR code does not contain valid JSON data.")
        except Exception as e:
            self.signals.error.emit(f"Failed to process data: {str(e)}")

    def _verify_hash(self, b64_encoded: str, sha256_hash: str, is_old_qr: bool) -> bool:
        """Verify the SHA-256 hash of the data."""
        if is_old_qr:
            payload = base64.b64decode(b64_encoded)
            computed_hash = hashlib.sha256(payload).hexdigest()
        else:
            computed_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()

        if computed_hash != sha256_hash:
            self.signals.error.emit("SHA-256 hash does not match. Data may be corrupted.")
            return False
        return True

    def _decrypt_data(self, b64_encoded: str, kdf_version: str) -> Optional[bytes]:
        """Decrypt the data."""
        try:
            payload = base64.b64decode(b64_encoded)
            salt = payload[:SecurityConfig.SALT_SIZE]
            iv = payload[SecurityConfig.SALT_SIZE:SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE]
            ciphertext = payload[SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE:]

            return CryptoHandler.decrypt_data(
                ciphertext,
                salt,
                iv,
                self.password,
                kdf_version
            )
        except Exception as e:
            self.signals.error.emit(f"Decryption failed: {str(e)}")
            return None
