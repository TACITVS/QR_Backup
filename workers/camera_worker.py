# workers/camera_worker.py

import logging
import cv2
import numpy as np
from PyQt5.QtGui import QPixmap, QImage
from PyQt5.QtCore import QThread, pyqtSignal, QObject
from PIL import Image
from pyzbar.pyzbar import decode

class CameraWorker(QObject):
    """Worker class for handling camera operations and QR code detection."""
    
    qr_code_detected = pyqtSignal(str)
    frame_received = pyqtSignal(QPixmap)

    def __init__(self, capture: cv2.VideoCapture):
        super().__init__()
        self.capture = capture
        self._running = True

    def run(self) -> None:
        """Main loop for capturing frames and processing QR codes."""
        try:
            while self._running:
                ret, frame = self.capture.read()
                if not ret:
                    continue
                
                # Convert frame to RGB for processing
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                self._process_frame(frame, rgb_frame)
                
        except Exception as e:
            logging.error(f"Error in camera worker: {e}")
        finally:
            self.capture.release()

    def _process_frame(self, frame: np.ndarray, rgb_frame: np.ndarray) -> None:
        """Process the frame to detect QR codes and emit signals."""
        # Decode QR codes
        decoded_objects = decode(Image.fromarray(rgb_frame))
        for obj in decoded_objects:
            try:
                data = obj.data.decode('utf-8')
                self.qr_code_detected.emit(data)
                self.stop()
                return
            except UnicodeDecodeError:
                continue

        # Convert frame for display
        height, width = frame.shape[:2]
        bytes_per_line = 3 * width
        q_img = QImage(frame.data, width, height, bytes_per_line, QImage.Format_BGR888)
        self.frame_received.emit(QPixmap.fromImage(q_img))

    def stop(self) -> None:
        """Stop the camera worker."""
        self._running = False
