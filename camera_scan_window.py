# gui/camera_scan_window.py

import cv2  # Import OpenCV
import logging
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QMessageBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QImage
from workers.camera_worker import CameraWorker
from PIL import Image
from pyzbar.pyzbar import decode

class CameraScanWindow(QWidget):
    """Window for scanning QR codes using the camera."""
    
    qr_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Camera QR Code Scanner")
        self.setGeometry(150, 150, 800, 600)
        self._setup_ui()
        self._initialize_camera()

    def _setup_ui(self) -> None:
        """Initialize the UI components."""
        layout = QVBoxLayout()
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.image_label)
        self.setLayout(layout)

    def _initialize_camera(self) -> None:
        """Initialize the camera and start the worker thread."""
        self.capture = cv2.VideoCapture(0)
        if not self.capture.isOpened():
            QMessageBox.critical(self, "Error", "Failed to open camera")
            self.close()
            return

        self.thread = QThread()
        self.worker = CameraWorker(self.capture)
        self.worker.moveToThread(self.thread)
        self.worker.qr_code_detected.connect(self._handle_qr_code)
        self.worker.frame_received.connect(self._update_image)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def _handle_qr_code(self, data: str) -> None:
        """Handle detected QR code data."""
        QMessageBox.information(self, "QR Code Detected", "QR Code has been detected. Closing camera.")
        self.qr_detected.emit(data)
        self.close()

    def _update_image(self, pixmap: QPixmap) -> None:
        """Update the displayed image with the latest frame."""
        self.image_label.setPixmap(pixmap.scaled(
            self.image_label.size(), 
            Qt.KeepAspectRatio
        ))

    def closeEvent(self, event) -> None:
        """Handle window close event."""
        if hasattr(self, 'worker'):
            self.worker.stop()
        if hasattr(self, 'thread'):
            self.thread.quit()
        event.accept()
