import sys
import pandas as pd
import numpy as np
from geopy.distance import geodesic
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QFileDialog, QMessageBox, QDialog

# Import KeyAuth
from keyauth import api, getchecksum

# KeyAuth initialization
keyauthapp = api(
    name="Koordinat",  # Application Name
    ownerid="QLIioia6XF",  # Owner ID
    secret="14b9a43c849dcff649ead10eff727816dd3937fcb2a3ce9a34bc7b942926c18a",  # Application Secret
    version="1.0",  # Application Version
    hash_to_check=getchecksum()
)

class LicenseDialog(QDialog):
    def __init__(self):
        super(LicenseDialog, self).__init__()
        self.setWindowTitle("Enter License Key")
        self.setGeometry(100, 100, 400, 200)

        self.label = QLabel("Please enter your license key:", self)
        self.label.move(20, 20)

        self.license_input = QLineEdit(self)
        self.license_input.setGeometry(20, 50, 360, 30)

        self.submit_button = QPushButton("Submit", self)
        self.submit_button.setGeometry(150, 100, 100, 40)
        self.submit_button.clicked.connect(self.check_license)

    def check_license(self):
        license_key = self.license_input.text()
        try:
            keyauthapp.license(license_key)
            QMessageBox.information(self, "Success", "License is valid!")
            self.accept()  # Close the dialog
        except Exception as e:
            QMessageBox.critical(self, "Error", "License is invalid: " + str(e))

class CircleCoordinateGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Giriş alanları
        self.name_label = QLabel('Name:', self)
        self.name_input = QLineEdit(self)

        self.lat_label = QLabel('Latitude:', self)
        self.lat_input = QLineEdit(self)

        self.lon_label = QLabel('Longitude:', self)
        self.lon_input = QLineEdit(self)

        self.radius_label = QLabel('Radius (meters):', self)
        self.radius_input = QLineEdit(self)

        self.num_points_label = QLabel('Number of points:', self)
        self.num_points_input = QLineEdit(self)

        self.browse_button = QPushButton('Save as...', self)
        self.browse_button.clicked.connect(self.saveFileDialog)

        self.generate_button = QPushButton('Generate Coordinates', self)
        self.generate_button.clicked.connect(self.generateCoordinates)

        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)
        layout.addWidget(self.lat_label)
        layout.addWidget(self.lat_input)
        layout.addWidget(self.lon_label)
        layout.addWidget(self.lon_input)
        layout.addWidget(self.radius_label)
        layout.addWidget(self.radius_input)
        layout.addWidget(self.num_points_label)
        layout.addWidget(self.num_points_input)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.generate_button)

        self.setLayout(layout)

    def saveFileDialog(self):
        options = QFileDialog.Options()
        self.fileName, _ = QFileDialog.getSaveFileName(self, "Save Coordinates", "", "CSV Files (*.csv);;All Files (*)", options=options)

    def generateCoordinates(self):
        try:
            lat = float(self.lat_input.text())
            lon = float(self.lon_input.text())
            radius = float(self.radius_input.text())
            num_points = int(self.num_points_input.text())

            center = (lat, lon)
            points = []
            angles = np.linspace(0, 360, num_points, endpoint=False)

            for angle in angles:
                destination = geodesic(meters=radius).destination(center, angle)
                points.append((destination.latitude, destination.longitude))

            df = pd.DataFrame(points, columns=['Latitude', 'Longitude'])
            df['Name'] = self.name_input.text()

            if self.fileName:
                df.to_csv(self.fileName, index=False)
                QMessageBox.information(self, "Success", "Coordinates generated and saved successfully.")
            else:
                QMessageBox.warning(self, "Warning", "No file selected. Please choose a file to save the coordinates.")
        except ValueError:
            QMessageBox.critical(self, "Error", "Please enter valid numbers for latitude, longitude, radius, and number of points.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

def main():
    app = QApplication(sys.argv)

    # Show License Dialog first
    license_dialog = LicenseDialog()
    if license_dialog.exec_() == QDialog.Accepted:
        # If license is valid, show the main window
        window = CircleCoordinateGenerator()
        window.setWindowTitle("Circle Coordinate Generator")
        window.setGeometry(100, 100, 400, 300)
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit()

if __name__ == '__main__':
    main()
