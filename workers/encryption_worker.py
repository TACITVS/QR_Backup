# workers/encryption_worker.py

import logging
import json
import base64
import hashlib
from io import BytesIO
from typing import Dict, Optional, Callable
from PyQt5.QtCore import QObject, pyqtSignal, QRunnable
from PyQt5.QtGui import QPixmap
from utils.crypto_handler import CryptoHandler
from utils.qr_code_generator import QRCodeGenerator
from utils.config import QRCodeParameters, SecurityConfig

class EncryptionWorkerSignals(QObject):
    """Signals for the EncryptionWorker."""
    finished = pyqtSignal()
    success = pyqtSignal(QPixmap, str, QRCodeParameters)
    error = pyqtSignal(str)

class EncryptionWorker(QRunnable):
    """Worker for handling encryption and QR code generation in a separate thread."""

    def __init__(self, data: bytes, password: str, qr_params: QRCodeParameters, signals: EncryptionWorkerSignals):
        super().__init__()
        self.data = data
        self.password = password
        self.qr_params = qr_params
        self.signals = signals

    def run(self) -> None:
        """Execute the encryption and QR code generation task."""
        try:
            # Encrypt data
            encrypted_payload = self._encrypt_data()
            if not encrypted_payload:
                return

            # Generate QR code
            self._generate_qr_code(encrypted_payload)

        except Exception as e:
            logging.error(f"Error in encryption worker: {e}")
            self.signals.error.emit(f"An unexpected error occurred: {str(e)}")
        finally:
            self.signals.finished.emit()

    def _encrypt_data(self) -> Optional[Dict[str, str]]:
        """Encrypt data and prepare the payload for the QR code."""
        try:
            salt, iv, ciphertext, kdf_version = CryptoHandler.encrypt_data(
                self.data,
                self.password,
                kdf_version="argon2"  # Default to Argon2 for new encryptions
            )

            payload = salt + iv + ciphertext
            b64_encoded = base64.b64encode(payload).decode('utf-8')
            sha256_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()

            return {
                "data": b64_encoded,
                "hash": sha256_hash,
                "kdf_version": kdf_version
            }
        except Exception as e:
            self.signals.error.emit(f"Encryption failed: {str(e)}")
            return None

    def _generate_qr_code(self, payload: Dict[str, str]) -> None:
        """Generate the QR code from the encrypted payload."""
        try:
            qr_content = json.dumps(payload)

            # Generate QR image
            img = QRCodeGenerator.create_qr_code(qr_content, self.qr_params)

            # Convert to QPixmap
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue(), "PNG")

            self.signals.success.emit(pixmap, qr_content, self.qr_params)

        except Exception as e:
            self.signals.error.emit(f"QR code generation failed: {str(e)}")
