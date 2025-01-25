# gui/main_window.py

import sys
import os
import base64
import hashlib
import json
import logging
from io import BytesIO
from typing import Optional, Tuple, Dict
from PyQt5.QtWidgets import (
    QWidget, QLabel, QPushButton, QLineEdit, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QTextEdit, QComboBox, QSpinBox, QGroupBox,
    QTabWidget, QCheckBox, QInputDialog
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt

from utils.crypto_handler import CryptoHandler
from utils.qr_code_generator import QRCodeGenerator
from utils.config import QRErrorCorrection, QRCodeParameters, QR_CAPACITY
from gui.camera_scan_window import CameraScanWindow
from pyzbar.pyzbar import decode
from PIL import Image

class QRBackupApp(QWidget):
    """Main application class for QR Backup."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QR Backup Application")
        self.setGeometry(100, 100, 1400, 800)
        
        # State management
        self.current_qr_params: Optional[QRCodeParameters] = None
        self.current_qr_content: Optional[str] = None
        self.original_text: str = ""
        
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialize the user interface."""
        main_layout = QVBoxLayout()
        
        # Initialize tab widget
        self.tabs = QTabWidget()
        self.encrypt_file_tab = self._create_encrypt_file_tab()
        self.encrypt_text_tab = self._create_encrypt_text_tab()
        
        self.tabs.addTab(self.encrypt_file_tab, "File Encryption")
        self.tabs.addTab(self.encrypt_text_tab, "Text Encryption")
        main_layout.addWidget(self.tabs)
        
        # Add QR display and decrypt sections
        self.qr_display_section = self._create_qr_display_section()
        self.decrypt_section = self._create_decrypt_section()
        
        main_layout.addLayout(self.qr_display_section)
        main_layout.addLayout(self.decrypt_section)
        
        self.setLayout(main_layout)

    def _create_encrypt_file_tab(self) -> QWidget:
        """Create the file encryption tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create encryption group
        encrypt_group = QGroupBox("Encrypt and Generate QR Code from File")
        encrypt_layout = QVBoxLayout()
        
        # File selection
        self.file_path = self._create_file_selection(encrypt_layout)
        
        # Password fields
        self.encrypt_file_pwd, self.encrypt_file_pwd_confirm = self._create_password_fields(encrypt_layout)
        
        # QR parameters
        self.file_error_correction, self.file_qr_version, self.file_box_size = (
            self._create_qr_parameters(encrypt_layout)
        )
        
        # Encrypt button
        encrypt_btn = QPushButton("Encrypt and Generate QR Code")
        encrypt_btn.clicked.connect(self._encrypt_file_and_generate_qr)
        encrypt_layout.addWidget(encrypt_btn)
        
        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)
        return tab

    def _create_file_selection(self, parent_layout: QVBoxLayout) -> QLineEdit:
        """Create file selection widgets."""
        file_layout = QHBoxLayout()
        file_path = QLineEdit()
        file_path.setPlaceholderText("Select a file to encrypt")
        
        file_btn = QPushButton("Browse")
        file_btn.clicked.connect(self._browse_file)
        
        file_layout.addWidget(file_path)
        file_layout.addWidget(file_btn)
        parent_layout.addLayout(file_layout)
        
        return file_path

    def _create_password_fields(self, parent_layout: QVBoxLayout) -> Tuple[QLineEdit, QLineEdit]:
        """Create password input fields."""
        pwd_layout = QHBoxLayout()
        
        pwd = QLineEdit()
        pwd.setEchoMode(QLineEdit.Password)
        pwd.setPlaceholderText("Enter password for encryption")
        
        pwd_confirm = QLineEdit()
        pwd_confirm.setEchoMode(QLineEdit.Password)
        pwd_confirm.setPlaceholderText("Confirm password")
        
        pwd_layout.addWidget(QLabel("Password:"))
        pwd_layout.addWidget(pwd)
        pwd_layout.addWidget(QLabel("Confirm:"))
        pwd_layout.addWidget(pwd_confirm)
        
        parent_layout.addLayout(pwd_layout)
        return pwd, pwd_confirm

    def _create_qr_parameters(self, parent_layout: QVBoxLayout) -> Tuple[QComboBox, QSpinBox, QSpinBox]:
        """Create QR code parameter inputs."""
        params_group = QGroupBox("QR Code Parameters (Optional)")
        params_layout = QHBoxLayout()
        
        # Error correction
        error_correction = QComboBox()
        error_correction.addItems([e.value for e in QRErrorCorrection])
        params_layout.addWidget(QLabel("Error Correction:"))
        params_layout.addWidget(error_correction)
        
        # Version
        qr_version = QSpinBox()
        qr_version.setRange(1, 40)
        qr_version.setValue(1)
        qr_version.setEnabled(False)
        params_layout.addWidget(QLabel("Version:"))
        params_layout.addWidget(qr_version)
        
        # Box size
        box_size = QSpinBox()
        box_size.setRange(1, 20)
        box_size.setValue(10)
        params_layout.addWidget(QLabel("Box Size:"))
        params_layout.addWidget(box_size)
        
        # Connect error correction to version enable/disable
        error_correction.currentTextChanged.connect(
            lambda text: qr_version.setEnabled(text != QRErrorCorrection.AUTO.value)
        )
        
        params_group.setLayout(params_layout)
        parent_layout.addWidget(params_group)
        
        return error_correction, qr_version, box_size

    def _browse_file(self) -> None:
        """Handle file browser dialog."""
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(
            self, 
            "Select File to Encrypt", 
            "", 
            "All Files (*)", 
            options=options
        )
        if file:
            self.file_path.setText(file)

    def _encrypt_file_and_generate_qr(self) -> None:
        """Handle file encryption and QR code generation."""
        try:
            # Validate inputs
            if not self._validate_encryption_inputs():
                return
            
            # Read file
            with open(self.file_path.text(), 'rb') as f:
                data = f.read()
            
            # Encrypt data
            encrypted_payload = self._encrypt_data(data)
            if not encrypted_payload:
                return
            
            # Generate QR code
            self._generate_and_display_qr(encrypted_payload)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            logging.error(f"Error in file encryption: {e}")

    def _validate_encryption_inputs(self) -> bool:
        """Validate encryption inputs."""
        if not self.file_path.text():
            QMessageBox.warning(self, "Input Error", "Please select a file to encrypt.")
            return False
            
        if not os.path.exists(self.file_path.text()):
            QMessageBox.warning(self, "File Error", "The selected file does not exist.")
            return False
            
        if not self._validate_passwords():
            return False
            
        return True

    def _validate_passwords(self) -> bool:
        """Validate password inputs."""
        pwd = self.encrypt_file_pwd.text()
        pwd_confirm = self.encrypt_file_pwd_confirm.text()
        
        if not pwd or not pwd_confirm:
            QMessageBox.warning(self, "Input Error", "Please enter and confirm your password.")
            return False
            
        if pwd != pwd_confirm:
            QMessageBox.warning(self, "Password Mismatch", "The passwords do not match.")
            self.encrypt_file_pwd.clear()
            self.encrypt_file_pwd_confirm.clear()
            return False
            
        if len(pwd) < SecurityConfig.MIN_PASSWORD_LENGTH:
            QMessageBox.warning(
                self, 
                "Invalid Password", 
                f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long."
            )
            return False
            
        return True

    def _encrypt_data(self, data: bytes) -> Optional[Dict[str, str]]:
        """Encrypt data and prepare QR payload."""
        try:
            # Encrypt the data using Argon2 by default
            salt, iv, ciphertext, kdf_version = CryptoHandler.encrypt_data(
                data, 
                self.encrypt_file_pwd.text(),
                kdf_version="argon2"  # Default to Argon2 for new encryptions
            )
            
            # Prepare payload
            payload = salt + iv + ciphertext
            b64_encoded = base64.b64encode(payload).decode('utf-8')
            
            # Compute hash based on whether kdf_version is present
            sha256_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()
            
            return {
                "data": b64_encoded,
                "hash": sha256_hash,
                "kdf_version": kdf_version  # Include KDF version in the payload
            }
            
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))
            logging.error(f"Encryption error: {e}")
            return None

    def _generate_and_display_qr(self, payload: Dict[str, str]) -> None:
        """Generate and display QR code."""
        try:
            qr_content = json.dumps(payload)
            
            # Get QR parameters
            params = self._get_qr_parameters(len(qr_content))
            if not params:
                return
                
            # Generate QR code
            img = QRCodeGenerator.create_qr_code(qr_content, params)
            
            # Convert to QPixmap and display
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue(), "PNG")
            
            # Display QR Code
            self.qr_label.setPixmap(pixmap.scaled(400, 400, Qt.KeepAspectRatio))
            
            # Store current QR data
            self.current_qr_content = qr_content
            self.current_qr_params = params
            
            QMessageBox.information(self, "Success", "QR Code generated successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "QR Generation Error", str(e))
            logging.error(f"QR generation error: {e}")

    def _get_qr_parameters(self, data_length: int) -> Optional[QRCodeParameters]:
        """Determine appropriate QR code parameters."""
        error_correction = self.file_error_correction.currentText()
        
        if error_correction == QRErrorCorrection.AUTO.value:
            # Auto-select parameters
            params = self._auto_select_qr_parameters(data_length)
            if params:
                QMessageBox.information(
                    self, 
                    "Auto-Selected QR Parameters",
                    f"Auto-selected QR Code version {params.version} with "
                    f"error correction level {params.error_correction}."
                )
            return params
        else:
            # Use manual parameters
            version = self.file_qr_version.value()
            if not self._validate_qr_capacity(data_length, error_correction, version):
                return None
                
            return QRCodeParameters(
                version=version,
                error_correction=error_correction,
                box_size=self.file_box_size.value()
            )

    def _validate_qr_capacity(self, data_length: int, error_correction: str, version: int) -> bool:
        """Validate if QR code can hold the data."""
        max_capacity = QR_CAPACITY.get(error_correction, {}).get(version, 0)
        if data_length > max_capacity:
            QMessageBox.warning(
                self, 
                "Data Size Error",
                f"The data size ({data_length} bytes) exceeds the maximum capacity "
                f"({max_capacity} bytes) for QR Code version {version} with error "
                f"correction level {error_correction}."
            )
            return False
        return True

    def _auto_select_qr_parameters(self, data_length: int) -> Optional[QRCodeParameters]:
        """Auto-select appropriate QR parameters based on data size."""
        error_correction = QRErrorCorrection.HIGH.value
        
        # Find minimum version that can hold the data
        for version in range(1, 41):
            if data_length <= QR_CAPACITY[error_correction].get(version, 0):
                return QRCodeParameters(
                    version=version,
                    error_correction=error_correction,
                    box_size=self.file_box_size.value()
                )
                
        QMessageBox.warning(
            self, 
            "Data Size Error",
            "Data is too large for QR code encoding."
        )
        return None

    def _create_encrypt_text_tab(self) -> QWidget:
        """Create the text encryption tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        encrypt_group = QGroupBox("Encrypt and Generate QR Code from Text")
        encrypt_layout = QVBoxLayout()
        
        # Text Input
        text_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt")
        text_layout.addWidget(self.text_input)
        encrypt_layout.addLayout(text_layout)
        
        # Obfuscation Option
        obfuscate_layout = QHBoxLayout()
        self.obfuscate_checkbox = QCheckBox("Obfuscate Text Display")
        obfuscate_layout.addWidget(self.obfuscate_checkbox)
        obfuscate_layout.addStretch()
        encrypt_layout.addLayout(obfuscate_layout)
        
        # Connect checkbox
        self.obfuscate_checkbox.stateChanged.connect(self._toggle_obfuscation)
        
        # Password fields
        self.encrypt_text_pwd, self.encrypt_text_pwd_confirm = self._create_password_fields(encrypt_layout)
        
        # QR parameters
        self.text_error_correction, self.text_qr_version, self.text_box_size = (
            self._create_qr_parameters(encrypt_layout)
        )
        
        # Encrypt button
        encrypt_btn = QPushButton("Encrypt and Generate QR Code")
        encrypt_btn.clicked.connect(self._encrypt_text_and_generate_qr)
        encrypt_layout.addWidget(encrypt_btn)
        
        encrypt_group.setLayout(encrypt_layout)
        layout.addWidget(encrypt_group)
        return tab

    def _toggle_obfuscation(self, state: int) -> None:
        """Handle text obfuscation toggle."""
        if state == Qt.Checked:
            self.original_text = self.text_input.toPlainText()
            obfuscated = self._obfuscate_text_preserve_structure(self.original_text)
            self.text_input.setPlainText(obfuscated)
        else:
            self.text_input.setPlainText(self.original_text)

    def _obfuscate_text_preserve_structure(self, text: str) -> str:
        """Replace each character with '*' except for newlines."""
        return ''.join(['*' if c != '\n' else '\n' for c in text])

    def _encrypt_text_and_generate_qr(self) -> None:
        """Handle text encryption and QR code generation."""
        try:
            text = self.text_input.toPlainText()
            if not text:
                QMessageBox.warning(self, "Input Error", "Please enter text to encrypt.")
                return
                
            if not self._validate_text_passwords():
                return
                
            # Convert text to bytes and encrypt
            text_bytes = text.encode('utf-8')
            encrypted_payload = self._encrypt_data(text_bytes)
            if not encrypted_payload:
                return
                
            # Generate QR code
            self._generate_and_display_qr_text(encrypted_payload)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            logging.error(f"Error in text encryption: {e}")

    def _validate_text_passwords(self) -> bool:
        """Validate text encryption passwords."""
        pwd = self.encrypt_text_pwd.text()
        pwd_confirm = self.encrypt_text_pwd_confirm.text()
        
        if not pwd or not pwd_confirm:
            QMessageBox.warning(self, "Input Error", "Please enter and confirm your password.")
            return False
            
        if pwd != pwd_confirm:
            QMessageBox.warning(self, "Password Mismatch", "The passwords do not match.")
            self.encrypt_text_pwd.clear()
            self.encrypt_text_pwd_confirm.clear()
            return False
            
        if len(pwd) < SecurityConfig.MIN_PASSWORD_LENGTH:
            QMessageBox.warning(
                self, 
                "Invalid Password", 
                f"Password must be at least {SecurityConfig.MIN_PASSWORD_LENGTH} characters long."
            )
            return False
            
        return True

    def _encrypt_data(self, data: bytes) -> Optional[Dict[str, str]]:
        """Encrypt data and prepare QR payload."""
        try:
            # Encrypt the data using Argon2 by default
            salt, iv, ciphertext, kdf_version = CryptoHandler.encrypt_data(
                data, 
                self.encrypt_text_pwd.text(),
                kdf_version="argon2"  # Default to Argon2 for new encryptions
            )
            
            # Prepare payload
            payload = salt + iv + ciphertext
            b64_encoded = base64.b64encode(payload).decode('utf-8')
            
            # Compute hash based on whether kdf_version is present
            sha256_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()
            
            return {
                "data": b64_encoded,
                "hash": sha256_hash,
                "kdf_version": kdf_version  # Include KDF version in the payload
            }
            
        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))
            logging.error(f"Encryption error: {e}")
            return None

    def _generate_and_display_qr_text(self, payload: Dict[str, str]) -> None:
        """Generate and display QR code for text."""
        try:
            qr_content = json.dumps(payload)
            
            # Get QR parameters
            params = self._get_text_qr_parameters(len(qr_content))
            if not params:
                return
                
            # Generate QR code
            img = QRCodeGenerator.create_qr_code(qr_content, params)
            
            # Convert to QPixmap and display
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            pixmap = QPixmap()
            pixmap.loadFromData(buffer.getvalue(), "PNG")
            
            # Display QR Code
            self.qr_label.setPixmap(pixmap.scaled(400, 400, Qt.KeepAspectRatio))
            
            # Store current QR data
            self.current_qr_content = qr_content
            self.current_qr_params = params
            
            QMessageBox.information(self, "Success", "QR Code generated successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "QR Generation Error", str(e))
            logging.error(f"QR generation error: {e}")

    def _get_text_qr_parameters(self, data_length: int) -> Optional[QRCodeParameters]:
        """Determine appropriate QR code parameters for text."""
        error_correction = self.text_error_correction.currentText()
        
        if error_correction == QRErrorCorrection.AUTO.value:
            # Auto-select parameters
            params = self._auto_select_qr_parameters(data_length)
            if params:
                QMessageBox.information(
                    self, 
                    "Auto-Selected QR Parameters",
                    f"Auto-selected QR Code version {params.version} with "
                    f"error correction level {params.error_correction}."
                )
            return params
        else:
            # Use manual parameters
            version = self.text_qr_version.value()
            if not self._validate_qr_capacity(data_length, error_correction, version):
                return None
                
            return QRCodeParameters(
                version=version,
                error_correction=error_correction,
                box_size=self.text_box_size.value()
            )

    def _create_qr_display_section(self) -> QVBoxLayout:
        """Create the QR code display section."""
        layout = QVBoxLayout()
        qr_display_group = QGroupBox("QR Code Display")
        qr_display_layout = QVBoxLayout()
        
        # QR Code Image
        self.qr_label = QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(400, 400)
        qr_display_layout.addWidget(self.qr_label)
        
        # Save QR Code Button
        save_qr_btn = QPushButton("Save QR Code")
        save_qr_btn.clicked.connect(self._save_qr_code)
        qr_display_layout.addWidget(save_qr_btn)
        
        qr_display_group.setLayout(qr_display_layout)
        layout.addWidget(qr_display_group)
        return layout

    def _save_qr_code(self) -> None:
        """Save the generated QR code."""
        if not self.current_qr_content:
            QMessageBox.warning(self, "No QR Code", "Please generate a QR code first.")
            return
            
        options = QFileDialog.Options()
        save_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Save QR Code",
            "",
            "PNG Image (*.png);;SVG Image (*.svg)",
            options=options
        )
        
        if not save_path:
            return
            
        try:
            if selected_filter == "SVG Image (*.svg)" or save_path.lower().endswith('.svg'):
                self._save_qr_as_svg(save_path)
            else:
                self._save_qr_as_png(save_path)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save QR Code: {str(e)}")
            logging.error(f"Error saving QR code: {e}")

    def _save_qr_as_svg(self, save_path: str) -> None:
        """Save QR code as SVG."""
        if not self.current_qr_params:
            QMessageBox.warning(self, "Error", "QR code parameters not available.")
            return
            
        img = QRCodeGenerator.create_svg_qr_code(
            self.current_qr_content,
            self.current_qr_params
        )
        img.save(save_path)
        QMessageBox.information(self, "Saved", f"QR Code saved as SVG to {save_path}")

    def _save_qr_as_png(self, save_path: str) -> None:
        """Save QR code as PNG."""
        if not self.qr_label.pixmap():
            QMessageBox.warning(self, "No QR Code", "Please generate a QR code first.")
            return
            
        self.qr_label.pixmap().save(save_path, "PNG")
        QMessageBox.information(self, "Saved", f"QR Code saved as PNG to {save_path}")
        
    def _create_decrypt_section(self) -> QVBoxLayout:
        """Create the decryption section."""
        layout = QVBoxLayout()
        decrypt_group = QGroupBox("Read and Decrypt QR Code")
        decrypt_layout = QVBoxLayout()
        
        # QR Code Selection
        qr_selection_layout = QHBoxLayout()
        self.qr_path = QLineEdit()
        self.qr_path.setPlaceholderText("Select a QR code image")
        qr_btn = QPushButton("Browse")
        qr_btn.clicked.connect(self._browse_qr)
        qr_selection_layout.addWidget(self.qr_path)
        qr_selection_layout.addWidget(qr_btn)
        decrypt_layout.addLayout(qr_selection_layout)
        
        # Camera Scan Button
        camera_scan_btn = QPushButton("Scan QR Code from Camera")
        camera_scan_btn.clicked.connect(self._scan_qr_from_camera)
        decrypt_layout.addWidget(camera_scan_btn)
        
        # Password Entry
        decrypt_pwd_layout = QHBoxLayout()
        self.decrypt_pwd = QLineEdit()
        self.decrypt_pwd.setEchoMode(QLineEdit.Password)
        self.decrypt_pwd.setPlaceholderText("Enter password for decryption")
        decrypt_pwd_layout.addWidget(QLabel("Password:"))
        decrypt_pwd_layout.addWidget(self.decrypt_pwd)
        decrypt_layout.addLayout(decrypt_pwd_layout)
        
        # Decrypt Button
        decrypt_btn = QPushButton("Read QR and Decrypt")
        decrypt_btn.clicked.connect(self._read_qr_and_decrypt)
        decrypt_layout.addWidget(decrypt_btn)
        
        # Decrypted Content Display
        self.decrypted_text = QTextEdit()
        self.decrypted_text.setReadOnly(True)
        decrypt_layout.addWidget(self.decrypted_text)
        
        decrypt_group.setLayout(decrypt_layout)
        layout.addWidget(decrypt_group)
        return layout

    def _browse_qr(self) -> None:
        """Handle QR code image file selection."""
        options = QFileDialog.Options()
        file, _ = QFileDialog.getOpenFileName(
            self,
            "Select QR Code Image",
            "",
            "Image Files (*.png *.jpg *.jpeg *.bmp *.svg)",
            options=options
        )
        if file:
            self.qr_path.setText(file)

    def _scan_qr_from_camera(self) -> None:
        """Initialize camera scanning window."""
        self.camera_window = CameraScanWindow()
        self.camera_window.qr_detected.connect(self._handle_camera_qr_code)
        self.camera_window.show()

    def _read_qr_and_decrypt(self) -> None:
        """Handle QR code reading and decryption."""
        try:
            if not self._validate_decrypt_inputs():
                return
                
            # Read and decode QR code
            qr_content = self._read_qr_code()
            if not qr_content:
                return
                
            # Process and decrypt data
            self._process_decrypted_data(qr_content)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            logging.error(f"Error in QR decryption: {e}")

    def _validate_decrypt_inputs(self) -> bool:
        """Validate decryption inputs."""
        if not self.qr_path.text():
            QMessageBox.warning(self, "Input Error", "Please select a QR code image.")
            return False
            
        if not os.path.exists(self.qr_path.text()):
            QMessageBox.warning(self, "File Error", "The selected QR code image does not exist.")
            return False
            
        if not self.decrypt_pwd.text():
            QMessageBox.warning(self, "Input Error", "Please enter the decryption password.")
            return False
            
        return True

    def _read_qr_code(self) -> Optional[str]:
        """Read and validate QR code content."""
        try:
            img = Image.open(self.qr_path.text())
            decoded_objects = decode(img)
            
            if not decoded_objects:
                QMessageBox.warning(self, "Decode Error", "No QR code found in the image.")
                return None
                
            return decoded_objects[0].data.decode('utf-8')
            
        except Exception as e:
            QMessageBox.critical(self, "QR Read Error", f"Failed to read QR code: {str(e)}")
            logging.error(f"Error reading QR code: {e}")
            return None

    def _process_decrypted_data(self, qr_content: str) -> None:
        """Process and handle decrypted data."""
        try:
            # Parse JSON content
            content = json.loads(qr_content)
            b64_encoded = content.get("data")
            sha256_hash = content.get("hash")
            kdf_version = content.get("kdf_version", "pbkdf2")  # Default to PBKDF2 for backward compatibility

            if not b64_encoded or not sha256_hash:
                QMessageBox.warning(self, "Data Error", "QR code does not contain valid data.")
                return

            # Determine if the QR code is from the old version (no kdf_version)
            is_old_qr = 'kdf_version' not in content

            if is_old_qr:
                # Old QR codes: Hash is on raw payload
                payload = base64.b64decode(b64_encoded)
                computed_hash = hashlib.sha256(payload).hexdigest()
            else:
                # New QR codes: Hash is on base64-encoded data
                computed_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()

            if computed_hash != sha256_hash:
                QMessageBox.warning(
                    self,
                    "Integrity Error",
                    "SHA-256 hash does not match. Data may be corrupted or tampered with."
                )
                return

            # Decrypt data
            decrypted_data = self._decrypt_data(b64_encoded, kdf_version)
            if not decrypted_data:
                return

            # Handle decrypted data
            self._handle_decrypted_data(decrypted_data)

        except json.JSONDecodeError:
            QMessageBox.warning(self, "Format Error", "QR code does not contain valid JSON data.")
        except Exception as e:
            QMessageBox.critical(self, "Process Error", f"Failed to process data: {str(e)}")
            logging.error(f"Error processing decrypted data: {e}")

    def _verify_data_hash(self, b64_encoded: str, sha256_hash: str, is_old_qr: bool) -> bool:
        """Verify SHA-256 hash of the data."""
        if is_old_qr:
            # Hash was computed on raw payload
            payload = base64.b64decode(b64_encoded)
            computed_hash = hashlib.sha256(payload).hexdigest()
        else:
            # Hash was computed on base64-encoded payload
            computed_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()

        if computed_hash != sha256_hash:
            QMessageBox.warning(
                self,
                "Integrity Error",
                "SHA-256 hash does not match. Data may be corrupted or tampered with."
            )
            return False
        return True

    def _decrypt_data(self, b64_encoded: str, kdf_version: str) -> Optional[bytes]:
        """Decrypt the encoded data using the specified KDF version."""
        try:
            # Base64 decode
            payload = base64.b64decode(b64_encoded)
            
            # Extract components
            salt = payload[:SecurityConfig.SALT_SIZE]
            iv = payload[SecurityConfig.SALT_SIZE:SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE]
            ciphertext = payload[SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE:]
            
            # Decrypt
            return CryptoHandler.decrypt_data(
                ciphertext,
                salt,
                iv,
                self.decrypt_pwd.text(),
                kdf_version
            )
            
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Failed to decrypt data: {str(e)}")
            logging.error(f"Decryption error: {e}")
            return None

    def _handle_decrypted_data(self, decrypted_data: bytes) -> None:
        """Handle the decrypted data appropriately."""
        # Ask user if they want to save the data
        save_option = QMessageBox.question(
            self,
            "Save Decrypted File",
            "Do you want to save the decrypted data as a file?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if save_option == QMessageBox.Yes:
            self._save_decrypted_file(decrypted_data)
        else:
            self._display_decrypted_content(decrypted_data)
            
        QMessageBox.information(self, "Success", "Data decrypted successfully!")

    def _save_decrypted_file(self, data: bytes) -> None:
        """Save decrypted data to file."""
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Decrypted File",
            "",
            "All Files (*)"
        )
        
        if save_path:
            try:
                with open(save_path, 'wb') as f:
                    f.write(data)
                QMessageBox.information(self, "Saved", f"Decrypted file saved to {save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save file: {str(e)}")
                logging.error(f"Error saving decrypted file: {e}")

    def _display_decrypted_content(self, data: bytes) -> None:
        """Display decrypted content in the text area."""
        try:
            # Try to decode as UTF-8 text
            text = data.decode('utf-8')
            self.decrypted_text.setPlainText(text)
        except UnicodeDecodeError:
            # If not valid UTF-8, show binary warning
            self.decrypted_text.setPlainText(
                "Decrypted data is binary and cannot be displayed as text.\n"
                "Please use the 'Save' option to save the data as a file."
            )

    def _handle_camera_qr_code(self, data: str) -> None:
        """Handle QR code data from camera scan."""
        try:
            # Parse JSON content
            content = json.loads(data)
            b64_encoded = content.get("data")
            sha256_hash = content.get("hash")
            kdf_version = content.get("kdf_version", "pbkdf2")  # Default to PBKDF2 for backward compatibility

            if not b64_encoded or not sha256_hash:
                QMessageBox.warning(self, "Data Error", "QR code does not contain valid data.")
                return

            # Determine if the QR code is from the old version (no kdf_version)
            is_old_qr = 'kdf_version' not in content

            if is_old_qr:
                # Old QR codes: Hash is on raw payload
                payload = base64.b64decode(b64_encoded)
                computed_hash = hashlib.sha256(payload).hexdigest()
            else:
                # New QR codes: Hash is on base64-encoded data
                computed_hash = hashlib.sha256(b64_encoded.encode('utf-8')).hexdigest()

            if computed_hash != sha256_hash:
                QMessageBox.warning(
                    self,
                    "Integrity Error",
                    "SHA-256 hash does not match. Data may be corrupted or tampered with."
                )
                return

            # Prompt for password
            password, ok = QInputDialog.getText(
                self,
                "Password Required",
                "Enter password for decryption:",
                QLineEdit.Password
            )
            
            if not ok or not password:
                QMessageBox.warning(self, "Input Error", "Password is required for decryption.")
                return

            # Decrypt data
            decrypted_data = CryptoHandler.decrypt_data(
                ciphertext=base64.b64decode(b64_encoded)[SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE:],
                salt=base64.b64decode(b64_encoded)[:SecurityConfig.SALT_SIZE],
                iv=base64.b64decode(b64_encoded)[SecurityConfig.SALT_SIZE:SecurityConfig.SALT_SIZE + SecurityConfig.AES_BLOCK_SIZE],
                password=password,
                kdf_version=kdf_version
            )

            if decrypted_data:
                self._handle_decrypted_data(decrypted_data)

        except json.JSONDecodeError:
            QMessageBox.warning(self, "Format Error", "QR code does not contain valid JSON data.")
        except Exception as e:
            QMessageBox.critical(self, "Process Error", f"Failed to process data: {str(e)}")
            logging.error(f"Error processing camera QR code: {e}")
