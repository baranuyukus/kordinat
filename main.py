'''
KeyAuth.cc Python Example

Go to https://keyauth.cc/app/ and click the Python tab. Copy that code and replace the existing keyauthapp instance in this file.

If you get an error saying it can't find module KeyAuth, try following this https://github.com/KeyAuth/KeyAuth-Python-Example#how-to-compile

If that doesn't work for you, you can paste the contents of KeyAuth.py ABOVE this comment and then remove the "from keyauth import api" and that should work too.

READ HERE TO LEARN ABOUT KEYAUTH FUNCTIONS https://github.com/KeyAuth/KeyAuth-Python-Example#keyauthapp-instance-definition
'''
import sys
import pandas as pd
import numpy as np
from geopy.distance import geodesic
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
from keyauth import api
import hashlib
from datetime import datetime

class KeyAuthCircleApp(QWidget):
    def __init__(self):
        super().__init__()
        self.keyauthapp = api(
            name="Koordinat",
            ownerid="QLIioia6XF",
            secret="14b9a43c849dcff649ead10eff727816dd3937fcb2a3ce9a34bc7b942926c18a",
            version="1.0",
            hash_to_check=self.getchecksum()
        )
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # KeyAuth giriş alanları
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Kullanıcı Adı")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Şifre")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.license_input = QLineEdit()
        self.license_input.setPlaceholderText("Lisans Anahtarı")
        layout.addWidget(self.license_input)

        button_layout = QHBoxLayout()
        login_button = QPushButton("Giriş")
        login_button.clicked.connect(self.login)
        button_layout.addWidget(login_button)

        register_button = QPushButton("Kayıt Ol")
        register_button.clicked.connect(self.register)
        button_layout.addWidget(register_button)

        upgrade_button = QPushButton("Yükselt")
        upgrade_button.clicked.connect(self.upgrade)
        button_layout.addWidget(upgrade_button)

        license_button = QPushButton("Lisans Doğrula")
        license_button.clicked.connect(self.verify_license)
        button_layout.addWidget(license_button)

        layout.addLayout(button_layout)

        self.info_label = QLabel()
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)

        # Circle Generator alanları (başlangıçta gizli)
        self.circle_widget = QWidget()
        circle_layout = QVBoxLayout()

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Name")
        circle_layout.addWidget(self.name_input)

        self.description_input = QLineEdit()
        self.description_input.setPlaceholderText("Description")
        circle_layout.addWidget(self.description_input)

        self.center_lat_input = QLineEdit()
        self.center_lat_input.setPlaceholderText("Merkez Latitude")
        circle_layout.addWidget(self.center_lat_input)

        self.center_long_input = QLineEdit()
        self.center_long_input.setPlaceholderText("Merkez Longitude")
        circle_layout.addWidget(self.center_long_input)

        self.radius_input = QLineEdit()
        self.radius_input.setPlaceholderText("Yarıçap (km)")
        circle_layout.addWidget(self.radius_input)

        self.num_points_input = QLineEdit()
        self.num_points_input.setPlaceholderText("Kaç adet koordinat oluşturulsun")
        circle_layout.addWidget(self.num_points_input)

        self.keywords_input = QLineEdit()
        self.keywords_input.setPlaceholderText("Keywords (virgülle ayırarak)")
        circle_layout.addWidget(self.keywords_input)

        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Website")
        circle_layout.addWidget(self.website_input)

        self.phone_number_input = QLineEdit()
        self.phone_number_input.setPlaceholderText("Phone Number")
        circle_layout.addWidget(self.phone_number_input)

        self.generate_button = QPushButton("Generate Coordinates")
        self.generate_button.clicked.connect(self.generate_coordinates)
        circle_layout.addWidget(self.generate_button)

        self.circle_widget.setLayout(circle_layout)
        self.circle_widget.hide()
        layout.addWidget(self.circle_widget)

        self.setLayout(layout)
        self.setWindowTitle('KeyAuth Circle Generator')
        self.setGeometry(300, 300, 400, 300)

    def getchecksum(self):
        md5_hash = hashlib.md5()
        file = open(''.join(sys.argv), "rb")
        md5_hash.update(file.read())
        digest = md5_hash.hexdigest()
        return digest

    def login(self):
        user = self.username_input.text()
        password = self.password_input.text()
        try:
            self.keyauthapp.login(user, password)
            self.show_user_info()
            self.show_circle_generator()
        except Exception as e:
            QMessageBox.warning(self, "Hata", str(e))

    def register(self):
        user = self.username_input.text()
        password = self.password_input.text()
        license = self.license_input.text()
        try:
            self.keyauthapp.register(user, password, license)
            self.show_user_info()
            self.show_circle_generator()
        except Exception as e:
            QMessageBox.warning(self, "Hata", str(e))

    def upgrade(self):
        user = self.username_input.text()
        license = self.license_input.text()
        try:
            self.keyauthapp.upgrade(user, license)
            self.show_user_info()
            self.show_circle_generator()
        except Exception as e:
            QMessageBox.warning(self, "Hata", str(e))

    def verify_license(self):
        key = self.license_input.text()
        try:
            self.keyauthapp.license(key)
            self.show_user_info()
            self.show_circle_generator()
        except Exception as e:
            QMessageBox.warning(self, "Hata", str(e))

    def show_user_info(self):
        info = f"Kullanıcı Adı: {self.keyauthapp.user_data.username}\n"
        info += f"IP Adresi: {self.keyauthapp.user_data.ip}\n"
        info += f"Hardware-Id: {self.keyauthapp.user_data.hwid}\n"
        info += f"Oluşturulma Tarihi: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Son Giriş: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Bitiş Tarihi: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.info_label.setText(info)

    def show_circle_generator(self):
        self.circle_widget.show()

    def generate_coordinates(self):
        try:
            name = self.name_input.text()
            description = self.description_input.text()
            center_lat = float(self.center_lat_input.text())
            center_long = float(self.center_long_input.text())
            radius = float(self.radius_input.text())
            num_points = int(self.num_points_input.text())
            keywords = self.keywords_input.text().split(',')
            website = self.website_input.text()
            phone_number = self.phone_number_input.text()

            coordinates = self.generate_concentric_circles(center_lat, center_long, radius, num_points)
            keywords_repeated = (keywords * (num_points // len(keywords) + 1))[:num_points]

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
    ex = KeyAuthCircleApp()
    ex.show()
    sys.exit(app.exec_())
