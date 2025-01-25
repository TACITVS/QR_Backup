# utils/config.py

from dataclasses import dataclass  # Ensure this import is present
from enum import Enum

class SecurityConfig:
    AES_KEY_SIZE = 32  # 256 bits
    AES_BLOCK_SIZE = 16
    PBKDF2_ITERATIONS = 100000
    SALT_SIZE = 16
    MIN_PASSWORD_LENGTH = 8
    PASSWORD_STRENGTH = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

class QRErrorCorrection(Enum):
    AUTO = 'Auto'
    LOW = 'L'
    MEDIUM = 'M'
    QUARTILE = 'Q'
    HIGH = 'H'

# QR Code capacities for different versions and error correction levels
QR_CAPACITY = {
    'L': {1: 2953, 2: 2331, 3: 1663, 4: 1273, 5: 877, 6: 691, 7: 509, 8: 365, 9: 293, 10: 209},
    'M': {1: 2331, 2: 1663, 3: 1273, 4: 877, 5: 691, 6: 509, 7: 365, 8: 293, 9: 209, 10: 161},
    'Q': {1: 1663, 2: 1273, 3: 877, 4: 691, 5: 509, 6: 365, 7: 293, 8: 209, 9: 161, 10: 113},
    'H': {1: 1273, 2: 877, 3: 691, 4: 509, 5: 365, 6: 293, 7: 209, 8: 161, 9: 113, 10: 87},
}

@dataclass
class QRCodeParameters:
    version: int
    error_correction: str
    box_size: int
    border: int = 4
