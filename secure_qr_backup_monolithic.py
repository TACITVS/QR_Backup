#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure QR Backup Application - Monolithic Edition

** --- CRITICAL SECURITY WARNING --- **
This script is provided for educational and demonstrational purposes ONLY.
It has NOT been professionally audited by security experts.
DO NOT use this script to secure real, high-value assets without fully
understanding the immense risks involved.

Risks include, but are not limited to:
- Bugs in this code leading to data loss or security vulnerabilities.
- Your computer being compromised by malware (keyloggers, spyware).
- Forgetting or losing your password, which makes data PERMANENTLY unrecoverable.
- Physical loss or damage to the generated QR code or JSON file.

For securing significant cryptocurrency assets, it is STRONGLY recommended to use a
trusted hardware wallet (e.g., Ledger, Trezor).
** --- YOU ARE USING THIS SCRIPT AT YOUR OWN RISK --- **

This application combines the streamlined single-file workflow of the reference
monolithic script with advanced features from the existing repository:
- AES-256-GCM authenticated encryption with password-based key derivation.
- Choice between PBKDF2-HMAC-SHA256 and Argon2id key derivation functions.
- Mnemonic generation (12- or 24-word BIP-39 phrases) using the english wordlist.
- Text obfuscation for privacy while typing.
- File encryption with automatic metadata capture.
- QR code configuration (error correction level and scale) with live preview.
- JSON export including metadata, checksums, and encryption parameters.
- QR/JSON import with verification and password-based decryption.

Dependencies (install with pip):
    PyQt5 cryptography argon2-cffi segno Pillow pyzbar opencv-python mnemonic
"""

import base64
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from typing import Any, Callable, Dict, Optional, Tuple

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QImage, QMovie, QPixmap
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSpinBox,
    QStatusBar,
    QStyle,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mnemonic import Mnemonic
from PIL import Image
from pyzbar.pyzbar import decode as pyzbar_decode
import cv2
import segno

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

SPEC_VERSION = "2.0"
APP_NAME = "SecureQRBackup"
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 480_000
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12
AES_KEY_SIZE_BYTES = 32  # 256-bit AES

ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 102400  # in kibibytes (~100 MiB)
ARGON2_PARALLELISM = 8

QR_CAPACITY_ESTIMATE = {
    "L": {1: 2953, 2: 2331, 3: 1663, 4: 1273, 5: 877, 6: 691, 7: 509, 8: 365, 9: 293, 10: 209},
    "M": {1: 2331, 2: 1663, 3: 1273, 4: 877, 5: 691, 6: 509, 7: 365, 8: 293, 9: 209, 10: 161},
    "Q": {1: 1663, 2: 1273, 3: 877, 4: 691, 5: 509, 6: 365, 7: 293, 8: 209, 9: 161, 10: 113},
    "H": {1: 1273, 2: 877, 3: 691, 4: 509, 5: 365, 6: 293, 7: 209, 8: 161, 9: 113, 10: 87},
}

APP_ICON_B64 = """
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
y7JsM4r+Aw1b9iV2p82lAAAAAElFTkSuQmCC
"""

# ---------------------------------------------------------------------------
# Helper Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class QRPreview:
    pixmap: QPixmap
    version: Any
    data_length: int


@dataclass
class EncryptionRequest:
    data_bytes: bytes
    password: str
    kdf: str
    payload_meta: Dict[str, Any]


@dataclass
class DecryptionResult:
    plaintext: bytes
    payload_meta: Dict[str, Any]
    document: Dict[str, Any]


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def load_icon_from_base64(data: str) -> QIcon:
    image_data = base64.b64decode(data)
    image = QImage.fromData(image_data)
    pixmap = QPixmap.fromImage(image)
    return QIcon(pixmap)


def get_standard_icon(widget: QWidget, icon: QStyle.StandardPixmap) -> QIcon:
    return widget.style().standardIcon(icon)


def derive_key(password: str, salt: bytes, kdf: str, params: Optional[Dict[str, Any]] = None) -> bytes:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    if kdf == "PBKDF2":
        iterations = (params or {}).get("iterations", PBKDF2_ITERATIONS)
        kdf_inst = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE_BYTES,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf_inst.derive(password.encode("utf-8"))

    if kdf == "Argon2id":
        params = params or {}
        time_cost = params.get("time_cost", ARGON2_TIME_COST)
        memory_cost = params.get("memory_cost", ARGON2_MEMORY_COST)
        parallelism = params.get("parallelism", ARGON2_PARALLELISM)
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=AES_KEY_SIZE_BYTES,
            type=Type.ID,
        )

    raise ValueError("Unsupported KDF selection.")


def _associated_data(payload_meta: Dict[str, Any]) -> bytes:
    """Create deterministic associated data from payload metadata."""
    return json.dumps(payload_meta, sort_keys=True).encode("utf-8")


def encrypt_payload(request: EncryptionRequest) -> Dict[str, Any]:
    salt = os.urandom(SALT_SIZE_BYTES)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    key = derive_key(request.password, salt, request.kdf)
    aesgcm = AESGCM(key)

    associated = _associated_data(request.payload_meta)
    ciphertext = aesgcm.encrypt(nonce, request.data_bytes, associated)
    checksum = hashlib.sha256(ciphertext).hexdigest()

    if request.kdf == "PBKDF2":
        kdf_params: Dict[str, Any] = {"iterations": PBKDF2_ITERATIONS, "hash": "SHA256"}
    else:
        kdf_params = {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
            "mode": "Argon2id",
        }

    document = {
        "specVersion": SPEC_VERSION,
        "appName": APP_NAME,
        "generatedAt": datetime.utcnow().isoformat() + "Z",
        "payload": request.payload_meta,
        "encryption": {
            "algorithm": "AES-256-GCM",
            "kdf": {"type": request.kdf, "params": kdf_params},
            "salt": base64.b64encode(salt).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "checksum": checksum,
        },
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return document


def decrypt_payload(document: Dict[str, Any], password: str) -> DecryptionResult:
    try:
        encryption_info = document["encryption"]
        payload_meta = document["payload"]
        ciphertext_b64 = document["ciphertext"]
    except KeyError as exc:
        raise ValueError(f"Missing field in encrypted document: {exc}") from exc

    kdf_info = encryption_info.get("kdf", {})
    kdf_type = kdf_info.get("type", "PBKDF2")
    kdf_params = kdf_info.get("params", {})

    salt = base64.b64decode(encryption_info.get("salt", ""))
    nonce = base64.b64decode(encryption_info.get("nonce", ""))
    ciphertext = base64.b64decode(ciphertext_b64)

    expected_checksum = encryption_info.get("checksum")
    if expected_checksum:
        actual_checksum = hashlib.sha256(ciphertext).hexdigest()
        if actual_checksum != expected_checksum:
            raise ValueError("Ciphertext integrity check failed (checksum mismatch).")

    key = derive_key(password, salt, kdf_type, kdf_params)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, _associated_data(payload_meta))
    return DecryptionResult(plaintext=plaintext, payload_meta=payload_meta, document=document)


def generate_bip39_mnemonic(strength_bits: int = 128) -> str:
    return Mnemonic("english").generate(strength=strength_bits)


def read_qr_code_data(filename: str) -> Optional[str]:
    try:
        img = Image.open(filename)
        decoded = pyzbar_decode(img)
        if decoded:
            return decoded[0].data.decode("utf-8")

        img_cv = cv2.imread(filename)
        if img_cv is not None:
            decoded_cv = pyzbar_decode(img_cv)
            if decoded_cv:
                return decoded_cv[0].data.decode("utf-8")
    except Exception as exc:
        raise IOError(f"Could not read or decode image file: {exc}") from exc
    return None


def format_size(num_bytes: int) -> str:
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024.0 or unit == "GB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024.0
    return f"{value:.2f} GB"


def obfuscate_text_preserve_structure(text: str) -> str:
    return ''.join('*' if ch != '\n' else '\n' for ch in text)


def estimate_qr_capacity(error: str, version: int) -> Optional[int]:
    return QR_CAPACITY_ESTIMATE.get(error, {}).get(version)


def generate_qr_preview(document: Dict[str, Any], error: str, scale: int, border: int = 4) -> QRPreview:
    data = json.dumps(document, separators=(",", ":"))
    qr = segno.make(data, error=error)
    buffer = BytesIO()
    qr.save(buffer, kind="png", scale=scale, border=border)
    pixmap = QPixmap()
    pixmap.loadFromData(buffer.getvalue(), "PNG")
    version = getattr(qr, "version", "auto")
    return QRPreview(pixmap=pixmap, version=version, data_length=len(data))


def ensure_password_strength(password: str, confirm: str) -> None:
    if password != confirm:
        raise ValueError("Passwords do not match.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")


def timestamp_meta() -> str:
    return datetime.utcnow().isoformat() + "Z"

# ---------------------------------------------------------------------------
# Worker for Asynchronous Cryptography
# ---------------------------------------------------------------------------

class CryptoWorker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, mode: str, payload: Dict[str, Any]):
        super().__init__()
        self.mode = mode
        self.payload = payload

    def run(self) -> None:
        try:
            if self.mode == "encrypt":
                request = EncryptionRequest(**self.payload)
                result = encrypt_payload(request)
            elif self.mode == "decrypt":
                result = decrypt_payload(self.payload["document"], self.payload["password"])
            else:
                raise ValueError("Invalid worker mode.")
            self.finished.emit(result)
        except Exception as exc:
            logging.exception("CryptoWorker failure: %s", exc)
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# Main Application Window
# ---------------------------------------------------------------------------

class SecureQRBackupApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Secure QR Backup Tool")
        self.setMinimumSize(960, 780)
        self.setWindowIcon(load_icon_from_base64(APP_ICON_B64))

        self.thread: Optional[QThread] = None
        self.worker: Optional[CryptoWorker] = None
        self.active_context: Optional[Any] = None

        self.current_document: Optional[Dict[str, Any]] = None
        self.decrypted_file_bytes: Optional[bytes] = None
        self.decrypted_file_meta: Optional[Dict[str, Any]] = None
        self.decrypt_pixmap: Optional[QPixmap] = None

        self._init_stylesheet()
        self._init_ui()

    # ------------------------------------------------------------------
    # Initialization Helpers
    # ------------------------------------------------------------------

    def _init_stylesheet(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background-color: #2E3440; }
            QWidget { color: #D8DEE9; font-family: 'Segoe UI', sans-serif; font-size: 15px; }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #4C566A;
                border-radius: 6px;
                margin-top: 1ex;
                padding: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
            }
            QLineEdit, QTextEdit {
                background-color: #3B4252;
                color: #ECEFF4;
                border: 1px solid #4C566A;
                border-radius: 4px;
                padding: 8px;
            }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #88C0D0; }
            QPushButton {
                background-color: #5E81AC;
                color: #ECEFF4;
                border: none;
                padding: 10px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton#AccentButton { background-color: #88C0D0; color: #2E3440; }
            QPushButton:hover { background-color: #81A1C1; }
            QPushButton#AccentButton:hover { background-color: #8FBCBB; }
            QPushButton:disabled { background-color: #4C566A; color: #6A7384; }
            QLabel#qrDisplayLabel {
                border: 2px dashed #4C566A;
                border-radius: 4px;
                background-color: #3B4252;
            }
            QStatusBar { background-color: #3B4252; }
            #CentralPanel {
                background-color: #3B4252;
                border: 1px solid #434C5E;
                border-radius: 8px;
                padding: 12px;
            }
            """
        )

    def _init_ui(self) -> None:
        self.tabs = QTabWidget()
        self.tab_mnemonic = QWidget()
        self.tab_text = QWidget()
        self.tab_file = QWidget()
        self.tab_decrypt = QWidget()

        self.tabs.addTab(self.tab_mnemonic, "Generate Mnemonic")
        self.tabs.addTab(self.tab_text, "Encrypt Text")
        self.tabs.addTab(self.tab_file, "Encrypt File")
        self.tabs.addTab(self.tab_decrypt, "Read & Decrypt")

        self._setup_mnemonic_tab()
        self._setup_text_tab()
        self._setup_file_tab()
        self._setup_decrypt_tab()

        central_widget = QWidget()
        central_layout = QVBoxLayout(central_widget)
        central_layout.addWidget(self.tabs)
        self.setCentralWidget(central_widget)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.loading_label = QLabel()
        self.loading_movie = QMovie(":/qt-project.org/styles/commonstyle/images/activity-indicator-16.gif")
        self.loading_label.setMovie(self.loading_movie)
        self.loading_label.hide()
        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.loading_label)

    # ------------------------------------------------------------------
    # UI Component Builders
    # ------------------------------------------------------------------

    def _create_qr_display_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("qrDisplayLabel")
        label.setAlignment(Qt.AlignCenter)
        label.setMinimumSize(260, 260)
        policy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        policy.setHeightForWidth(True)
        label.setSizePolicy(policy)
        return label

    def _create_password_fields(self, parent_layout: QGridLayout, row: int) -> Tuple[QLineEdit, QLineEdit]:
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.Password)
        confirm_edit = QLineEdit()
        confirm_edit.setEchoMode(QLineEdit.Password)

        show_btn = QPushButton()
        show_btn.setIcon(get_standard_icon(self, QStyle.SP_DialogNoButton))
        show_btn.setCheckable(True)
        show_btn.setToolTip("Show/Hide Password")

        def toggle_visibility(checked: bool) -> None:
            mode = QLineEdit.Normal if checked else QLineEdit.Password
            password_edit.setEchoMode(mode)
            confirm_edit.setEchoMode(mode)
            icon = QStyle.SP_DialogYesButton if checked else QStyle.SP_DialogNoButton
            show_btn.setIcon(get_standard_icon(self, icon))

        show_btn.toggled.connect(toggle_visibility)

        parent_layout.addWidget(QLabel("Password:"), row, 0)
        parent_layout.addWidget(password_edit, row, 1)
        parent_layout.addWidget(show_btn, row, 2)
        parent_layout.addWidget(QLabel("Confirm:"), row + 1, 0)
        parent_layout.addWidget(confirm_edit, row + 1, 1)
        parent_layout.addWidget(QWidget(), row + 1, 2)

        return password_edit, confirm_edit

    def _create_kdf_selector(self) -> QComboBox:
        combo = QComboBox()
        combo.addItem("Argon2id (Recommended)", "Argon2id")
        combo.addItem("PBKDF2-HMAC-SHA256", "PBKDF2")
        return combo

    def _create_qr_options(self) -> Tuple[QComboBox, QSpinBox]:
        error_combo = QComboBox()
        error_combo.addItem("Low (L)", "L")
        error_combo.addItem("Medium (M)", "M")
        error_combo.addItem("Quartile (Q)", "Q")
        error_combo.addItem("High (H)", "H")
        error_combo.setCurrentIndex(3)  # Default to High

        scale_spin = QSpinBox()
        scale_spin.setRange(2, 20)
        scale_spin.setValue(8)
        return error_combo, scale_spin

    def _create_preview_section(self, tab: QWidget) -> Tuple[QGroupBox, QPushButton, QLabel, QLabel, QPushButton, QPushButton]:
        preview_group = QGroupBox("5. Encrypt & Preview")
        preview_layout = QVBoxLayout()
        preview_button = QPushButton("Encrypt & Preview QR")
        preview_button.setObjectName("AccentButton")
        preview_button.setIcon(get_standard_icon(self, QStyle.SP_ComputerIcon))
        qr_display = self._create_qr_display_label("Preview")
        info_label = QLabel("No preview generated yet.")
        info_label.setWordWrap(True)
        preview_layout.addWidget(preview_button)
        preview_layout.addWidget(qr_display, 1)
        preview_layout.addWidget(info_label)
        preview_group.setLayout(preview_layout)

        save_group = QGroupBox("6. Save Outputs")
        save_layout = QVBoxLayout()
        save_qr = QPushButton("Save QR Image")
        save_qr.setIcon(get_standard_icon(self, QStyle.SP_DialogSaveButton))
        save_json = QPushButton("Save JSON File")
        save_json.setIcon(get_standard_icon(self, QStyle.SP_FileDialogDetailedView))
        save_layout.addWidget(save_qr)
        save_layout.addWidget(save_json)
        save_layout.addStretch()
        save_group.setLayout(save_layout)

        container = QHBoxLayout()
        container.addWidget(preview_group, 2)
        container.addWidget(save_group, 1)

        outer_group = QGroupBox()
        outer_group.setLayout(container)

        return outer_group, preview_button, qr_display, info_label, save_qr, save_json

    # ------------------------------------------------------------------
    # Tab Setup
    # ------------------------------------------------------------------
    def _setup_mnemonic_tab(self) -> None:
        tab = self.tab_mnemonic
        outer = QHBoxLayout(tab)
        outer.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(820)
        layout = QVBoxLayout(panel)
        layout.setSpacing(14)

        # Step 1: Options
        options_group = QGroupBox("1. Generate Mnemonic Phrase")
        options_layout = QGridLayout()
        radio_12 = QRadioButton("12 Words (Good)")
        radio_24 = QRadioButton("24 Words (Best)")
        radio_12.setChecked(True)
        btn_generate = QPushButton("Generate New")
        btn_generate.setIcon(get_standard_icon(self, QStyle.SP_BrowserReload))
        options_layout.addWidget(radio_12, 0, 0)
        options_layout.addWidget(radio_24, 0, 1)
        options_layout.addWidget(btn_generate, 1, 0, 1, 2)
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Step 2: Display
        data_group = QGroupBox("2. Record Your Phrase")
        data_layout = QVBoxLayout()
        data_input = QTextEdit()
        data_input.setReadOnly(True)
        data_input.setPlaceholderText("Click 'Generate New' to create a mnemonic.")
        data_layout.addWidget(data_input)
        buttons = QHBoxLayout()
        buttons.addStretch()
        btn_copy = QPushButton("Copy")
        btn_copy.setIcon(get_standard_icon(self, QStyle.SP_FileLinkIcon))
        btn_clear = QPushButton("Clear")
        btn_clear.setIcon(get_standard_icon(self, QStyle.SP_DialogResetButton))
        buttons.addWidget(btn_copy)
        buttons.addWidget(btn_clear)
        data_layout.addLayout(buttons)
        data_group.setLayout(data_layout)
        layout.addWidget(data_group)

        # Step 3: Security Settings
        security_group = QGroupBox("3. Security Settings")
        security_layout = QGridLayout()
        password_edit, password_confirm = self._create_password_fields(security_layout, 0)
        kdf_combo = self._create_kdf_selector()
        security_layout.addWidget(QLabel("Key Derivation:"), 2, 0)
        security_layout.addWidget(kdf_combo, 2, 1)
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)

        # Step 4: QR Options
        qr_group = QGroupBox("4. QR Code Options")
        qr_layout = QGridLayout()
        error_combo, scale_spin = self._create_qr_options()
        qr_layout.addWidget(QLabel("Error Correction:"), 0, 0)
        qr_layout.addWidget(error_combo, 0, 1)
        qr_layout.addWidget(QLabel("Scale:"), 1, 0)
        qr_layout.addWidget(scale_spin, 1, 1)
        qr_hint = QLabel("Higher error correction or scale increases QR size but improves readability.")
        qr_hint.setWordWrap(True)
        qr_layout.addWidget(qr_hint, 2, 0, 1, 2)
        qr_group.setLayout(qr_layout)
        layout.addWidget(qr_group)

        preview_container, preview_button, qr_display, info_label, save_qr, save_json = self._create_preview_section(tab)
        layout.addWidget(preview_container)

        layout.addStretch()
        outer.addWidget(panel)
        outer.addStretch()

        tab.data_input = data_input
        tab.password_edit = password_edit
        tab.password_confirm = password_confirm
        tab.kdf_combo = kdf_combo
        tab.error_combo = error_combo
        tab.scale_spin = scale_spin
        tab.qr_display = qr_display
        tab.preview_info = info_label
        tab.save_qr_button = save_qr
        tab.save_json_button = save_json
        tab.preview_button = preview_button

        tab.preview_button.clicked.connect(lambda: self._start_preview(tab, "mnemonic"))
        save_qr.clicked.connect(lambda: self._save_encrypted_output(tab, True))
        save_json.clicked.connect(lambda: self._save_encrypted_output(tab, False))

        btn_generate.clicked.connect(lambda: self._generate_mnemonic_text(tab, 256 if radio_24.isChecked() else 128))
        btn_copy.clicked.connect(lambda: self._copy_to_clipboard(data_input))
        btn_clear.clicked.connect(lambda: self._clear_text(tab))

        data_input.textChanged.connect(lambda: self._mark_preview_stale(tab))
        password_edit.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        password_confirm.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        error_combo.currentIndexChanged.connect(lambda: self._mark_preview_stale(tab))
        scale_spin.valueChanged.connect(lambda: self._mark_preview_stale(tab))

        tab.data_getter = lambda: self._get_mnemonic_payload(tab)
        tab.data_checker = lambda: bool(tab.data_input.toPlainText().strip())
        self._initialize_tab_state(tab)

    def _setup_text_tab(self) -> None:
        tab = self.tab_text
        outer = QHBoxLayout(tab)
        outer.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(820)
        layout = QVBoxLayout(panel)
        layout.setSpacing(14)

        text_group = QGroupBox("1. Enter Secret Text")
        text_layout = QVBoxLayout()
        text_input = QTextEdit()
        text_input.setPlaceholderText("Enter text to encrypt")
        text_layout.addWidget(text_input)
        obfuscate_checkbox = QCheckBox("Obfuscate Text Display")
        obfuscate_checkbox.setToolTip("Temporarily replace characters with '*' while viewing.")
        text_layout.addWidget(obfuscate_checkbox)
        text_group.setLayout(text_layout)
        layout.addWidget(text_group)

        security_group = QGroupBox("2. Security Settings")
        security_layout = QGridLayout()
        password_edit, password_confirm = self._create_password_fields(security_layout, 0)
        kdf_combo = self._create_kdf_selector()
        security_layout.addWidget(QLabel("Key Derivation:"), 2, 0)
        security_layout.addWidget(kdf_combo, 2, 1)
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)

        qr_group = QGroupBox("3. QR Code Options")
        qr_layout = QGridLayout()
        error_combo, scale_spin = self._create_qr_options()
        qr_layout.addWidget(QLabel("Error Correction:"), 0, 0)
        qr_layout.addWidget(error_combo, 0, 1)
        qr_layout.addWidget(QLabel("Scale:"), 1, 0)
        qr_layout.addWidget(scale_spin, 1, 1)
        qr_hint = QLabel("Large text may exceed QR capacity; JSON export is always available.")
        qr_hint.setWordWrap(True)
        qr_layout.addWidget(qr_hint, 2, 0, 1, 2)
        qr_group.setLayout(qr_layout)
        layout.addWidget(qr_group)

        preview_container, preview_button, qr_display, info_label, save_qr, save_json = self._create_preview_section(tab)
        layout.addWidget(preview_container)

        layout.addStretch()
        outer.addWidget(panel)
        outer.addStretch()

        tab.data_input = text_input
        tab.obfuscate_checkbox = obfuscate_checkbox
        tab.original_text = ""
        tab.password_edit = password_edit
        tab.password_confirm = password_confirm
        tab.kdf_combo = kdf_combo
        tab.error_combo = error_combo
        tab.scale_spin = scale_spin
        tab.preview_button = preview_button
        tab.qr_display = qr_display
        tab.preview_info = info_label
        tab.save_qr_button = save_qr
        tab.save_json_button = save_json

        preview_button.clicked.connect(lambda: self._start_preview(tab, "text"))
        save_qr.clicked.connect(lambda: self._save_encrypted_output(tab, True))
        save_json.clicked.connect(lambda: self._save_encrypted_output(tab, False))

        def on_text_changed() -> None:
            if not obfuscate_checkbox.isChecked():
                tab.original_text = text_input.toPlainText()
            self._mark_preview_stale(tab)

        text_input.textChanged.connect(on_text_changed)

        def toggle_obfuscation(state: int) -> None:
            if state == Qt.Checked:
                tab.original_text = text_input.toPlainText()
                text_input.blockSignals(True)
                text_input.setPlainText(obfuscate_text_preserve_structure(tab.original_text))
                text_input.blockSignals(False)
                text_input.setReadOnly(True)
            else:
                text_input.setReadOnly(False)
                text_input.blockSignals(True)
                text_input.setPlainText(tab.original_text)
                text_input.blockSignals(False)
            self._mark_preview_stale(tab)

        obfuscate_checkbox.stateChanged.connect(toggle_obfuscation)
        password_edit.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        password_confirm.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        error_combo.currentIndexChanged.connect(lambda: self._mark_preview_stale(tab))
        scale_spin.valueChanged.connect(lambda: self._mark_preview_stale(tab))

        tab.data_getter = lambda: self._get_text_payload(tab)
        tab.data_checker = lambda: bool(self._get_text_preview(tab).strip())
        self._initialize_tab_state(tab)

    def _setup_file_tab(self) -> None:
        tab = self.tab_file
        outer = QHBoxLayout(tab)
        outer.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(820)
        layout = QVBoxLayout(panel)
        layout.setSpacing(14)

        file_group = QGroupBox("1. Select File")
        file_layout = QGridLayout()
        file_path_edit = QLineEdit()
        file_path_edit.setPlaceholderText("Choose a file to encrypt")
        browse_btn = QPushButton("Browse")
        browse_btn.setIcon(get_standard_icon(self, QStyle.SP_DialogOpenButton))
        file_layout.addWidget(QLabel("File:"), 0, 0)
        file_layout.addWidget(file_path_edit, 0, 1)
        file_layout.addWidget(browse_btn, 0, 2)
        file_info_label = QLabel("No file selected.")
        file_info_label.setWordWrap(True)
        file_layout.addWidget(file_info_label, 1, 0, 1, 3)
        file_hint = QLabel("Tip: Very large files may be better stored via JSON export rather than QR codes.")
        file_hint.setWordWrap(True)
        file_layout.addWidget(file_hint, 2, 0, 1, 3)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        security_group = QGroupBox("2. Security Settings")
        security_layout = QGridLayout()
        password_edit, password_confirm = self._create_password_fields(security_layout, 0)
        kdf_combo = self._create_kdf_selector()
        security_layout.addWidget(QLabel("Key Derivation:"), 2, 0)
        security_layout.addWidget(kdf_combo, 2, 1)
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)

        qr_group = QGroupBox("3. QR Code Options")
        qr_layout = QGridLayout()
        error_combo, scale_spin = self._create_qr_options()
        qr_layout.addWidget(QLabel("Error Correction:"), 0, 0)
        qr_layout.addWidget(error_combo, 0, 1)
        qr_layout.addWidget(QLabel("Scale:"), 1, 0)
        qr_layout.addWidget(scale_spin, 1, 1)
        qr_group.setLayout(qr_layout)
        layout.addWidget(qr_group)

        preview_container, preview_button, qr_display, info_label, save_qr, save_json = self._create_preview_section(tab)
        layout.addWidget(preview_container)

        layout.addStretch()
        outer.addWidget(panel)
        outer.addStretch()

        tab.file_path_edit = file_path_edit
        tab.file_info_label = file_info_label
        tab.password_edit = password_edit
        tab.password_confirm = password_confirm
        tab.kdf_combo = kdf_combo
        tab.error_combo = error_combo
        tab.scale_spin = scale_spin
        tab.preview_button = preview_button
        tab.qr_display = qr_display
        tab.preview_info = info_label
        tab.save_qr_button = save_qr
        tab.save_json_button = save_json

        browse_btn.clicked.connect(lambda: self._browse_file(tab))
        preview_button.clicked.connect(lambda: self._start_preview(tab, "file"))
        save_qr.clicked.connect(lambda: self._save_encrypted_output(tab, True))
        save_json.clicked.connect(lambda: self._save_encrypted_output(tab, False))

        file_path_edit.textChanged.connect(lambda: self._on_file_path_changed(tab))
        password_edit.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        password_confirm.textChanged.connect(lambda: self._update_encryption_tab_state(tab))
        error_combo.currentIndexChanged.connect(lambda: self._mark_preview_stale(tab))
        scale_spin.valueChanged.connect(lambda: self._mark_preview_stale(tab))

        tab.data_getter = lambda: self._get_file_payload(tab)
        tab.data_checker = lambda: os.path.isfile(tab.file_path_edit.text().strip())
        self._initialize_tab_state(tab)

    def _setup_decrypt_tab(self) -> None:
        outer = QHBoxLayout(self.tab_decrypt)
        outer.addStretch()

        panel = QWidget()
        panel.setObjectName("CentralPanel")
        panel.setMaximumWidth(820)
        layout = QVBoxLayout(panel)
        layout.setSpacing(14)

        file_group = QGroupBox("1. Select Source File")
        file_layout = QVBoxLayout()
        button_layout = QHBoxLayout()
        btn_open_qr = QPushButton("Open QR Image")
        btn_open_qr.setIcon(get_standard_icon(self, QStyle.SP_DialogOpenButton))
        btn_open_json = QPushButton("Open JSON File")
        btn_open_json.setIcon(get_standard_icon(self, QStyle.SP_FileDialogInfoView))
        button_layout.addWidget(btn_open_qr)
        button_layout.addWidget(btn_open_json)
        button_layout.addStretch()
        file_layout.addLayout(button_layout)
        self.decrypt_qr_display = self._create_qr_display_label("Select a QR code to preview")
        file_layout.addWidget(self.decrypt_qr_display, 1)
        self.loaded_file_label = QLabel("No file loaded.")
        self.loaded_file_label.setAlignment(Qt.AlignCenter)
        file_layout.addWidget(self.loaded_file_label)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        decrypt_group = QGroupBox("2. Decrypt")
        decrypt_layout = QVBoxLayout()
        pass_layout = QHBoxLayout()
        self.decrypt_password = QLineEdit()
        self.decrypt_password.setEchoMode(QLineEdit.Password)
        self.decrypt_password.setPlaceholderText("Enter password for decryption")
        pass_layout.addWidget(QLabel("Password:"))
        pass_layout.addWidget(self.decrypt_password)
        show_btn = QPushButton()
        show_btn.setIcon(get_standard_icon(self, QStyle.SP_DialogNoButton))
        show_btn.setCheckable(True)

        def toggle_decrypt_visibility(checked: bool) -> None:
            self.decrypt_password.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
            icon = QStyle.SP_DialogYesButton if checked else QStyle.SP_DialogNoButton
            show_btn.setIcon(get_standard_icon(self, icon))

        show_btn.toggled.connect(toggle_decrypt_visibility)
        pass_layout.addWidget(show_btn)
        decrypt_layout.addLayout(pass_layout)

        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setObjectName("AccentButton")
        self.btn_decrypt.setIcon(get_standard_icon(self, QStyle.SP_DialogApplyButton))
        decrypt_layout.addWidget(self.btn_decrypt)

        self.decryption_info_label = QLabel("No payload loaded.")
        self.decryption_info_label.setWordWrap(True)
        decrypt_layout.addWidget(self.decryption_info_label)

        button_row = QHBoxLayout()
        self.btn_copy_decrypted = QPushButton("Copy Text")
        self.btn_copy_decrypted.setEnabled(False)
        self.btn_copy_decrypted.setIcon(get_standard_icon(self, QStyle.SP_FileLinkIcon))
        self.btn_save_decrypted_file = QPushButton("Save Decrypted File")
        self.btn_save_decrypted_file.setEnabled(False)
        self.btn_save_decrypted_file.setIcon(get_standard_icon(self, QStyle.SP_DialogSaveButton))
        button_row.addWidget(self.btn_copy_decrypted)
        button_row.addWidget(self.btn_save_decrypted_file)
        button_row.addStretch()
        decrypt_layout.addLayout(button_row)

        self.decrypted_output = QTextEdit()
        self.decrypted_output.setReadOnly(True)
        self.decrypted_output.setPlaceholderText("Decrypted content will appear here.")
        decrypt_layout.addWidget(self.decrypted_output)

        decrypt_group.setLayout(decrypt_layout)
        layout.addWidget(decrypt_group)

        layout.addStretch()
        outer.addWidget(panel)
        outer.addStretch()

        btn_open_qr.clicked.connect(self._open_qr_file)
        btn_open_json.clicked.connect(self._open_json_file)
        self.btn_decrypt.clicked.connect(self._decrypt_action)
        self.btn_copy_decrypted.clicked.connect(self._copy_decrypted_text)
        self.btn_save_decrypted_file.clicked.connect(self._save_decrypted_file)

    # ------------------------------------------------------------------
    # Encryption Helpers
    # ------------------------------------------------------------------

    def _initialize_tab_state(self, tab: QWidget) -> None:
        tab.envelope = None
        tab.qr_pixmap = None
        tab.preview_valid = False
        tab.preview_options = {}
        tab.preview_info.setText("No preview generated yet.")
        tab.qr_display.clear()
        tab.qr_display.setText("Preview")
        tab.preview_button.setEnabled(False)
        tab.save_qr_button.setEnabled(False)
        tab.save_json_button.setEnabled(False)
        self._update_encryption_tab_state(tab)

    def _update_encryption_tab_state(self, tab: QWidget) -> None:
        data_ok = tab.data_checker()
        password = tab.password_edit.text()
        confirm = tab.password_confirm.text()
        passwords_ok = bool(password) and password == confirm and len(password) >= MIN_PASSWORD_LENGTH
        tab.preview_button.setEnabled(data_ok and passwords_ok)
        tab.save_qr_button.setEnabled(getattr(tab, "preview_valid", False))
        tab.save_json_button.setEnabled(getattr(tab, "preview_valid", False))

    def _mark_preview_stale(self, tab: QWidget, message: str = "Preview invalidated. Re-run encryption.") -> None:
        if not hasattr(tab, "preview_button"):
            return
        tab.preview_valid = False
        tab.preview_options = {}
        tab.qr_pixmap = None
        tab.qr_display.clear()
        tab.qr_display.setText("Preview")
        tab.preview_info.setText(message)
        self._update_encryption_tab_state(tab)

    def _start_preview(self, tab: QWidget, payload_type: str) -> None:
        try:
            password = tab.password_edit.text()
            confirm = tab.password_confirm.text()
            ensure_password_strength(password, confirm)
            data_bytes, payload_meta = tab.data_getter()
            payload_meta.setdefault("type", payload_type)
            payload_meta.setdefault("timestamp", timestamp_meta())
            request = {
                "data_bytes": data_bytes,
                "password": password,
                "kdf": tab.kdf_combo.currentData(),
                "payload_meta": payload_meta,
            }
            tab.pending_options = {
                "error": tab.error_combo.currentData(),
                "scale": tab.scale_spin.value(),
            }
            tab.preview_info.setText("Encrypting...")
            self._start_crypto_operation("encrypt", request, tab)
        except ValueError as exc:
            QMessageBox.warning(self, "Input Error", str(exc))
        except Exception as exc:
            QMessageBox.critical(self, "Encryption Error", str(exc))

    def _handle_encryption_success(self, tab: QWidget, document: Dict[str, Any]) -> None:
        try:
            options = getattr(tab, "pending_options", {
                "error": tab.error_combo.currentData(),
                "scale": tab.scale_spin.value(),
            })
            preview = generate_qr_preview(document, options["error"], options["scale"])
        except Exception as exc:
            QMessageBox.critical(self, "QR Generation Error", f"Failed to create QR preview: {exc}")
            tab.preview_info.setText("QR preview failed. Try adjusting options.")
            tab.preview_valid = False
            self.status_label.setText("QR preview generation failed.")
            return

        tab.envelope = document
        tab.qr_pixmap = preview.pixmap
        self._scale_pixmap(tab.qr_display, preview.pixmap)
        version = preview.version
        info_parts = [f"QR version {version}", f"payload length {preview.data_length} chars"]
        if isinstance(version, int):
            capacity = estimate_qr_capacity(options["error"], version)
            if capacity:
                info_parts.append(f"approx. capacity {capacity} bytes")
        tab.preview_info.setText(" | ".join(info_parts))
        tab.preview_valid = True
        tab.preview_options = options
        self._update_encryption_tab_state(tab)
        self.status_label.setText("Encryption successful. Preview ready.")

    def _save_encrypted_output(self, tab: QWidget, as_qr: bool) -> None:
        if not getattr(tab, "preview_valid", False) or not getattr(tab, "envelope", None):
            QMessageBox.warning(self, "No Data", "Generate a preview before saving.")
            return

        document = tab.envelope
        options = tab.preview_options

        try:
            if as_qr:
                filename, _ = QFileDialog.getSaveFileName(
                    self, "Save QR Image", "", "PNG Image (*.png)"
                )
                if not filename:
                    return
                qr = segno.make(json.dumps(document, separators=(",", ":")), error=options["error"])
                qr.save(filename, scale=options["scale"], border=4)
            else:
                filename, _ = QFileDialog.getSaveFileName(
                    self, "Save JSON File", "", "JSON File (*.json)"
                )
                if not filename:
                    return
                with open(filename, "w", encoding="utf-8") as fh:
                    json.dump(document, fh, indent=4)

            QMessageBox.information(self, "Success", f"Saved to:\n{filename}")
            self.status_label.setText(f"Saved output to {os.path.basename(filename)}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Error", f"Failed to save file: {exc}")
            self.status_label.setText("Save operation failed.")

    def _generate_mnemonic_text(self, tab: QWidget, strength_bits: int) -> None:
        phrase = generate_bip39_mnemonic(strength_bits)
        tab.data_input.blockSignals(True)
        tab.data_input.setPlainText(phrase)
        tab.data_input.blockSignals(False)
        tab.preview_valid = False
        self._update_encryption_tab_state(tab)
        self.status_label.setText(f"Generated {len(phrase.split())}-word mnemonic.")

    def _clear_text(self, tab: QWidget) -> None:
        if hasattr(tab, "data_input"):
            tab.data_input.clear()
        if hasattr(tab, "original_text"):
            tab.original_text = ""
        self._mark_preview_stale(tab, "Cleared. Re-run encryption when ready.")

    def _copy_to_clipboard(self, text_edit: QTextEdit) -> None:
        text = text_edit.toPlainText()
        if not text:
            QMessageBox.information(self, "Clipboard", "Nothing to copy.")
            return
        QApplication.clipboard().setText(text)
        QMessageBox.warning(
            self,
            "Security Warning",
            "Data copied to clipboard. Paste it only into trusted locations and clear the clipboard afterwards.",
        )
        self.status_label.setText("Data copied to clipboard.")

    def _get_mnemonic_payload(self, tab: QWidget) -> Tuple[bytes, Dict[str, Any]]:
        text = tab.data_input.toPlainText()
        phrase = " ".join(text.split())
        if not phrase:
            raise ValueError("Generate or enter a mnemonic phrase before encrypting.")
        data_bytes = phrase.encode("utf-8")
        tab.data_input.blockSignals(True)
        tab.data_input.setPlainText(phrase)
        tab.data_input.blockSignals(False)
        return data_bytes, {
            "type": "mnemonic",
            "format": "utf-8",
            "length": len(data_bytes),
            "words": len(phrase.split()),
        }

    def _get_text_preview(self, tab: QWidget) -> str:
        return tab.original_text if tab.obfuscate_checkbox.isChecked() else tab.data_input.toPlainText()

    def _get_text_payload(self, tab: QWidget) -> Tuple[bytes, Dict[str, Any]]:
        text = self._get_text_preview(tab)
        if not text.strip():
            raise ValueError("Please enter text to encrypt.")
        data_bytes = text.encode("utf-8")
        return data_bytes, {
            "type": "text",
            "format": "utf-8",
            "length": len(data_bytes),
            "lines": text.count("\n") + 1,
        }

    def _get_file_payload(self, tab: QWidget) -> Tuple[bytes, Dict[str, Any]]:
        path = tab.file_path_edit.text().strip()
        if not path or not os.path.isfile(path):
            raise ValueError("Select a valid file before encrypting.")
        with open(path, "rb") as fh:
            data = fh.read()
        return data, {
            "type": "file",
            "format": "binary",
            "length": len(data),
            "filename": os.path.basename(path),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _browse_file(self, tab: QWidget) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if filename:
            tab.file_path_edit.setText(filename)
            self._on_file_path_changed(tab)

    def _on_file_path_changed(self, tab: QWidget) -> None:
        path = tab.file_path_edit.text().strip()
        if os.path.isfile(path):
            size = os.path.getsize(path)
            tab.file_info_label.setText(f"Selected: {os.path.basename(path)} ({format_size(size)})")
        else:
            tab.file_info_label.setText("No file selected.")
        self._mark_preview_stale(tab)
        self._update_encryption_tab_state(tab)

    # ------------------------------------------------------------------
    # Decryption Helpers
    # ------------------------------------------------------------------

    def _reset_decryption_state(self) -> None:
        self.current_document = None
        self.decrypted_output.clear()
        self.decrypted_file_bytes = None
        self.decrypted_file_meta = None
        self.decrypt_qr_display.clear()
        self.decrypt_qr_display.setText("Select a QR code to preview")
        self.decrypt_pixmap = None
        self.loaded_file_label.setText("No file loaded.")
        self.decryption_info_label.setText("No payload loaded.")
        self.btn_copy_decrypted.setEnabled(False)
        self.btn_save_decrypted_file.setEnabled(False)
        self.status_label.setText("Ready")

    def _open_qr_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open QR Image", "", "Image Files (*.png *.jpg *.jpeg *.bmp)"
        )
        if not filename:
            return
        try:
            payload = read_qr_code_data(filename)
            if not payload:
                raise ValueError("No QR code data detected in the selected image.")
            document = json.loads(payload)
            self._load_document(document, os.path.basename(filename))
            self.decrypt_pixmap = QPixmap(filename)
            self._scale_pixmap(self.decrypt_qr_display, self.decrypt_pixmap)
            self.status_label.setText("QR code loaded.")
        except Exception as exc:
            QMessageBox.critical(self, "Read Error", f"Failed to load QR code: {exc}")
            self._reset_decryption_state()

    def _open_json_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Open JSON File", "", "JSON Files (*.json)")
        if not filename:
            return
        try:
            with open(filename, "r", encoding="utf-8") as fh:
                document = json.load(fh)
            self._load_document(document, os.path.basename(filename))
            self.decrypt_qr_display.clear()
            self.decrypt_qr_display.setText("JSON file loaded.")
            self.decrypt_pixmap = None
            self.status_label.setText("JSON file loaded.")
        except Exception as exc:
            QMessageBox.critical(self, "File Error", f"Failed to read JSON file: {exc}")
            self._reset_decryption_state()

    def _load_document(self, document: Dict[str, Any], label: str) -> None:
        self.current_document = document
        self.decrypted_output.clear()
        self.decrypted_file_bytes = None
        self.decrypted_file_meta = None
        self.btn_copy_decrypted.setEnabled(False)
        self.btn_save_decrypted_file.setEnabled(False)
        self.loaded_file_label.setText(f"Loaded: {label}")
        self.decryption_info_label.setText(self._describe_document(document))

    def _describe_document(self, document: Dict[str, Any]) -> str:
        payload = document.get("payload", {})
        enc = document.get("encryption", {})
        parts = []
        payload_type = payload.get("type", "unknown")
        length = payload.get("length")
        if length is not None:
            parts.append(f"Type: {payload_type} ({length} bytes)")
        else:
            parts.append(f"Type: {payload_type}")
        kdf_info = enc.get("kdf", {})
        parts.append(f"KDF: {kdf_info.get('type', 'unknown')}")
        parts.append(f"Algorithm: {enc.get('algorithm', 'unknown')}")
        generated = document.get("generatedAt")
        if generated:
            parts.append(f"Generated: {generated}")
        return " | ".join(parts)

    def _decrypt_action(self) -> None:
        if not self.current_document:
            QMessageBox.warning(self, "No Data", "Load a QR or JSON file first.")
            return
        password = self.decrypt_password.text()
        if not password:
            QMessageBox.warning(self, "No Password", "Enter the password to decrypt.")
            return
        self.decrypted_output.clear()
        self.btn_copy_decrypted.setEnabled(False)
        self.btn_save_decrypted_file.setEnabled(False)
        self._start_crypto_operation("decrypt", {
            "document": self.current_document,
            "password": password,
        }, "decrypt")

    def _handle_decryption_success(self, result: DecryptionResult) -> None:
        plaintext = result.plaintext
        meta = result.payload_meta
        payload_type = meta.get("type", "text")
        self.decryption_info_label.setText(self._describe_document(result.document))

        if payload_type in {"text", "mnemonic"}:
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                text = plaintext.decode("utf-8", errors="replace")
            self.decrypted_output.setPlainText(text)
            self.btn_copy_decrypted.setEnabled(True)
            self.btn_save_decrypted_file.setEnabled(False)
            self.status_label.setText("Decryption successful.")
        else:
            self.decrypted_file_bytes = plaintext
            self.decrypted_file_meta = meta
            self.decrypted_output.setPlainText(
                "Binary data decrypted. Use 'Save Decrypted File' to write the output to disk."
            )
            self.btn_copy_decrypted.setEnabled(False)
            self.btn_save_decrypted_file.setEnabled(True)
            self.status_label.setText("Decryption successful. Binary data ready to save.")

    def _copy_decrypted_text(self) -> None:
        text = self.decrypted_output.toPlainText()
        if not text.strip():
            QMessageBox.information(self, "Clipboard", "Nothing to copy.")
            return
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Clipboard", "Decrypted text copied to clipboard.")
        self.status_label.setText("Decrypted text copied.")

    def _save_decrypted_file(self) -> None:
        if self.decrypted_file_bytes is None:
            QMessageBox.warning(self, "No File", "No binary payload available to save.")
            return
        default = "decrypted.bin"
        if self.decrypted_file_meta and self.decrypted_file_meta.get("filename"):
            default = f"decrypted_{self.decrypted_file_meta['filename']}"
        filename, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", default, "All Files (*)")
        if not filename:
            return
        try:
            with open(filename, "wb") as fh:
                fh.write(self.decrypted_file_bytes)
            QMessageBox.information(self, "Saved", f"Decrypted file saved to:\n{filename}")
            self.status_label.setText(f"Decrypted file saved to {os.path.basename(filename)}")
        except Exception as exc:
            QMessageBox.critical(self, "Save Error", f"Failed to save file: {exc}")
            self.status_label.setText("Failed to save decrypted file.")

    # ------------------------------------------------------------------
    # Thread Management
    # ------------------------------------------------------------------

    def _start_crypto_operation(self, mode: str, payload: Dict[str, Any], context: Any) -> None:
        if self.thread and self.thread.isRunning():
            QMessageBox.warning(self, "Busy", "Another cryptographic operation is already in progress.")
            return
        self.active_context = context
        self.loading_label.show()
        self.loading_movie.start()
        self.tabs.setEnabled(False)
        self.status_label.setText(f"{mode.capitalize()}ing data...")

        self.thread = QThread()
        self.worker = CryptoWorker(mode, payload)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._handle_crypto_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.error.connect(self._handle_crypto_error)
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._cleanup_thread)
        self.thread.start()

    def _handle_crypto_finished(self, result: Any) -> None:
        mode = getattr(self.worker, "mode", None)
        context = self.active_context
        self._stop_loading_state()
        self.active_context = None
        if mode == "encrypt" and isinstance(context, QWidget):
            self._handle_encryption_success(context, result)
        elif mode == "decrypt" and isinstance(result, DecryptionResult):
            self._handle_decryption_success(result)
        elif mode == "decrypt":
            # Result may be a plain dict if dataclass conversion was bypassed
            plaintext = result.get("plaintext")
            meta = result.get("payload_meta", {})
            doc = result.get("document", {})
            self._handle_decryption_success(DecryptionResult(plaintext=plaintext, payload_meta=meta, document=doc))

    def _handle_crypto_error(self, message: str) -> None:
        self._stop_loading_state()
        self.active_context = None
        if "InvalidTag" in message or "tag" in message.lower():
            QMessageBox.critical(self, "Decryption Failed", "Incorrect password or data integrity check failed.")
        else:
            QMessageBox.critical(self, "Error", message)
        self.status_label.setText("Operation failed.")

    def _stop_loading_state(self) -> None:
        self.loading_movie.stop()
        self.loading_label.hide()
        self.tabs.setEnabled(True)

    def _cleanup_thread(self) -> None:
        if self.thread:
            self.thread.deleteLater()
            self.thread = None
        self.worker = None

    # ------------------------------------------------------------------
    # Rendering Helpers
    # ------------------------------------------------------------------

    def _scale_pixmap(self, label: QLabel, pixmap: Optional[QPixmap]) -> None:
        if pixmap and label.width() > 0 and label.height() > 0:
            label.setPixmap(pixmap.scaled(label.width(), label.height(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        for tab in (self.tab_mnemonic, self.tab_text, self.tab_file):
            if hasattr(tab, "qr_pixmap") and tab.qr_pixmap is not None:
                self._scale_pixmap(tab.qr_display, tab.qr_pixmap)
        if getattr(self, "decrypt_pixmap", None) is not None:
            self._scale_pixmap(self.decrypt_qr_display, self.decrypt_pixmap)

# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SecureQRBackupApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
