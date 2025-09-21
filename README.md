# Secure QR Backup Application

This repository now ships a single-file PyQt5 application – `secure_qr_backup_monolithic.py` – that combines the most useful ideas from the original multi-module prototype and the monolithic reference implementation.  It provides an end-to-end workflow for generating secrets, encrypting data, producing QR codes/JSON backups, and restoring that data with strong password-based encryption.

> **Security Warning**
> The tool is provided for educational purposes only.  It has not been audited by security professionals.  Treat any secrets that touch an online machine or clipboard as compromised.

## Highlights

- **Authenticated Encryption (AES-256-GCM):** Password-protected backups with integrity checks (SHA-256 checksum + AEAD tag).
- **Flexible KDFs:** Choose between PBKDF2-HMAC-SHA256 or Argon2id for key derivation (Argon2id is the default).
- **Mnemonic Generator:** Create 12- or 24-word BIP-39 phrases using the official English word list.
- **Text & File Encryption:** Secure free-form text (with optional obfuscation while viewing) or binary files, embedding metadata such as filenames and lengths.
- **Configurable QR Output:** Select QR error-correction levels and pixel scale, with live previews and automatic capacity hints.
- **Rich Imports:** Decrypt from QR images or JSON files, verifying metadata before prompting for the password.
- **Responsive UI:** Encryption and decryption happen on a worker thread to keep the interface smooth.

## Requirements

Install Python 3.8+ and the dependencies listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

The key packages are:

- `PyQt5` for the desktop interface.
- `cryptography` + `argon2-cffi` for password-based key derivation and AES-GCM.
- `segno`, `Pillow`, `pyzbar`, and `opencv-python` for QR creation and decoding.
- `mnemonic` for BIP-39 phrase generation.

## Running the App

```bash
python secure_qr_backup_monolithic.py
```

The application opens with four tabs:

1. **Generate Mnemonic** – Create a 12- or 24-word phrase, set a password/KDF, and preview QR/JSON backups.
2. **Encrypt Text** – Paste or type text (optionally obfuscated on screen) and encrypt it to QR/JSON.
3. **Encrypt File** – Select a file, choose encryption settings, and preview/save backups.  Large binaries are best stored as JSON.
4. **Read & Decrypt** – Load a QR image or JSON backup, enter the password, and view/save the decrypted data.

## Tips

- Use long, unique passwords (minimum 12 characters enforced) and store them safely—there is no recovery if forgotten.
- QR codes have capacity limits; the app reports the estimated QR version/capacity for each preview.  For large data, prefer JSON exports.
- Copying secrets to the clipboard is dangerous.  Only do so when necessary and clear your clipboard afterwards.

## License

This project is released under the MIT License.  See `LICENSE` for details.
