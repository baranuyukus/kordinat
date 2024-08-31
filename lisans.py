import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QStackedWidget)
from keyauth import api  # KeyAuth Python SDK'sını kullanıyoruz
import hashlib
from coordinate_generator import CircleCoordinateGenerator  # Koordinat oluşturma sınıfını import ediyoruz

# checksum fonksiyonu, dosyanın hash'ini hesaplamak için kullanılır
def getchecksum():
    md5_hash = hashlib.md5()
    with open(sys.argv[0], "rb") as f:
        content = f.read()
    md5_hash.update(content)
    return md5_hash.hexdigest()

# KeyAuth API tanımı
keyauthapp = api(
    name="Koordinat",  # Uygulama adı
    ownerid="QLIioia6XF",  # Owner ID
    secret="14b9a43c849dcff649ead10eff727816dd3937fcb2a3ce9a34bc7b942926c18a",  # Secret Key
    version="1.0",  # Uygulama versiyonu
    hash_to_check=getchecksum()
)

# Login ekranı sınıfı
class LoginWindow(QWidget):
    def __init__(self, stacked_widget):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.username_label = QLabel('Username:', self)
        self.username_input = QLineEdit(self)

        self.password_label = QLabel('Password:', self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)  # Şifreyi gizli girdi

        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)

        self.setLayout(layout)
        self.setWindowTitle('Login')

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        # KeyAuth ile giriş yapma
        keyauthapp.login(username, password)

        if keyauthapp.user_data.username:  # Giriş başarılı olduysa
            QMessageBox.information(self, "Başarılı", "Giriş başarılı!")
            self.stacked_widget.setCurrentIndex(1)  # Koordinat oluşturma ekranına geç
        else:
            QMessageBox.warning(self, "Hata", "Giriş başarısız! Lütfen bilgilerinizi kontrol edin.")

if __name__ == '__main__':
    app = QApplication(sys.argv)

    # Stacked Widget oluşturuluyor, bu sayede login ve ana uygulama arasında geçiş yapılabilir
    stacked_widget = QStackedWidget()

    # Login ekranı
    login_window = LoginWindow(stacked_widget)
    stacked_widget.addWidget(login_window)

    # Koordinat oluşturma ekranı
    coordinate_generator = CircleCoordinateGenerator()
    stacked_widget.addWidget(coordinate_generator)

    # Başlangıçta login ekranı gösteriliyor
    stacked_widget.setCurrentIndex(0)
    stacked_widget.show()

    sys.exit(app.exec_())
