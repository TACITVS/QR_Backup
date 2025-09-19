# main.py

import sys
import logging
from PyQt5.QtWidgets import QApplication, QMessageBox
from gui.main_window import QRBackupApp

def main():
    """Main application entry point."""
    try:
        # Configure logging
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

        # Initialize the application
        app = QApplication(sys.argv)

        # Set application style
        app.setStyle('Fusion')

        # Create and show the main window
        window = QRBackupApp()
        window.show()

        # Start the event loop
        sys.exit(app.exec_())

    except Exception as e:
        # Handle any unexpected errors during startup
        if 'app' in locals():
            QMessageBox.critical(None, "Fatal Error", f"Application failed to start: {str(e)}")
        else:
            print(f"Critical error during startup: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
