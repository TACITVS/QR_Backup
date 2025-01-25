# utils/qr_code_generator.py

import qrcode
from qrcode.image.svg import SvgImage
from PIL import Image
from .config import QRCodeParameters

class QRCodeGenerator:
    """Handles QR code generation and processing."""
    
    @staticmethod
    def create_qr_code(data: str, params: QRCodeParameters) -> Image.Image:
        """Generate a QR code image."""
        qr = qrcode.QRCode(
            version=params.version,
            error_correction=getattr(qrcode.constants, f"ERROR_CORRECT_{params.error_correction}"),
            box_size=params.box_size,
            border=params.border,
        )
        qr.add_data(data)
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white")

    @staticmethod
    def create_svg_qr_code(data: str, params: QRCodeParameters) -> Image.Image:
        """Generate a QR code image in SVG format."""
        qr = qrcode.QRCode(
            version=params.version,
            error_correction=getattr(qrcode.constants, f"ERROR_CORRECT_{params.error_correction}"),
            box_size=params.box_size,
            border=params.border,
            image_factory=SvgImage
        )
        qr.add_data(data)
        qr.make(fit=True)
        return qr.make_image()
