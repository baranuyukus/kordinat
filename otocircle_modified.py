import sys
import pandas as pd
import numpy as np
from geopy.distance import geodesic
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QFileDialog, QMessageBox

class CircleCoordinateGenerator(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Giriş alanları
        self.name_label = QLabel('Name:', self)
        self.name_input = QLineEdit(self)

        self.description_label = QLabel('Description:', self)
        self.description_input = QLineEdit(self)

        self.center_lat_label = QLabel('Merkez Latitude:', self)
        self.center_lat_input = QLineEdit(self)

        self.center_long_label = QLabel('Merkez Longitude:', self)
        self.center_long_input = QLineEdit(self)

        self.radius_label = QLabel('Yarıçap (km):', self)
        self.radius_input = QLineEdit(self)

        self.num_points_label = QLabel('Kaç adet koordinat oluşturulsun:', self)
        self.num_points_input = QLineEdit(self)

        self.keywords_label = QLabel('Keywords (virgülle ayırarak):', self)
        self.keywords_input = QLineEdit(self)

        self.website_label = QLabel('Website:', self)
        self.website_input = QLineEdit(self)

        self.phone_number_label = QLabel('Phone Number:', self)
        self.phone_number_input = QLineEdit(self)

        # Gönder butonu
        self.submit_button = QPushButton('Generate Coordinates', self)
        self.submit_button.clicked.connect(self.generate_coordinates)

        # Düzene widget'ları ekle
        layout.addWidget(self.name_label)
        layout.addWidget(self.name_input)
        layout.addWidget(self.description_label)
        layout.addWidget(self.description_input)
        layout.addWidget(self.center_lat_label)
        layout.addWidget(self.center_lat_input)
        layout.addWidget(self.center_long_label)
        layout.addWidget(self.center_long_input)
        layout.addWidget(self.radius_label)
        layout.addWidget(self.radius_input)
        layout.addWidget(self.num_points_label)
        layout.addWidget(self.num_points_input)
        layout.addWidget(self.keywords_label)
        layout.addWidget(self.keywords_input)
        layout.addWidget(self.website_label)
        layout.addWidget(self.website_input)
        layout.addWidget(self.phone_number_label)
        layout.addWidget(self.phone_number_input)
        layout.addWidget(self.submit_button)

        self.setLayout(layout)
        self.setWindowTitle('Circle Coordinate Generator')

    def generate_coordinates(self):
        try:
            # Giriş değerlerini oku
            name = self.name_input.text()
            description = self.description_input.text()
            center_lat = float(self.center_lat_input.text())
            center_long = float(self.center_long_input.text())
            radius = float(self.radius_input.text())
            num_points = int(self.num_points_input.text())
            keywords = self.keywords_input.text().split(',')
            website = self.website_input.text()
            phone_number = self.phone_number_input.text()

            # İç içe çemberleri oluştur
            coordinates = self.generate_concentric_circles(center_lat, center_long, radius, num_points)

            # Anahtar kelimeleri eşit şekilde tekrarla
            keywords_repeated = (keywords * (num_points // len(keywords) + 1))[:num_points]

            # Excel için veriyi hazırla
            data = {
                "Name": [name] * num_points,
                "Description": [description] * num_points,
                "Keyword": keywords_repeated,
                "Website": [website] * num_points,
                "Phone Number": [phone_number] * num_points,
                "Latitude": [coord[0] for coord in coordinates],
                "Longitude": [coord[1] for coord in coordinates]
            }
            df = pd.DataFrame(data)

            # DataFrame'i Excel'e kaydet
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Excel Files (*.xlsx);;All Files (*)", options=options)
            if file_name:
                num_files = (num_points // 2000) + (1 if num_points % 2000 != 0 else 0)
                for i in range(num_files):
                    start_idx = i * 2000
                    end_idx = min((i + 1) * 2000, num_points)
                    df_subset = df.iloc[start_idx:end_idx]
                    subset_file_name = f"{file_name}_part_{i+1}.xlsx"
                    df_subset.to_excel(subset_file_name, index=False)
                    QMessageBox.information(self, "Başarılı", f"{subset_file_name} başarıyla kaydedildi.")
            else:
                QMessageBox.warning(self, "Hata", "Kaydetme işlemi iptal edildi.")

        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Bir hata oluştu: {e}")

    def generate_concentric_circles(self, center_lat, center_long, max_radius, total_points):
        points = []
        num_circles = total_points // 2000
        points_per_circle = 2000
        radius_step = max_radius / num_circles

        for i in range(num_circles):
            current_radius = (i + 1) * radius_step
            circle_points = self.generate_circle_coordinates(center_lat, center_long, current_radius, points_per_circle)
            points.extend(circle_points)

        return points

    def generate_circle_coordinates(self, center_lat, center_long, radius, num_points):
        points = []
        angle_step = 360 / num_points
        for i in range(num_points):
            angle = angle_step * i
            destination = geodesic(kilometers=radius).destination((center_lat, center_long), angle)
            points.append((destination.latitude, destination.longitude))
        return points

if __name__ == '__main__':
    app = QApplication(sys.argv)
    generator = CircleCoordinateGenerator()
    generator.show()
    sys.exit(app.exec_())
