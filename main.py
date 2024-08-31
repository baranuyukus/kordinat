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
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QGroupBox, QFormLayout, QComboBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon
import hashlib
from datetime import datetime
import os
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import platform  # check platform
import subprocess  # needed for mac device
import hmac # signature checksum
import hashlib # signature checksum
import random

try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == 'nt':
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        if len(ownerid) != 10 and len(secret) != 64:
            print("Go to Manage Applications on dashboard, copy python code, and replace code in main.py with that")
            time.sleep(3)
            os._exit(1)
    
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):
        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(3)
            os._exit(1)

        sent_key = str(uuid4())[:16]
        
        self.enckey = sent_key + "-" + self.secret
        
        post_data = {
            "type": "init",
            "ver": self.version,
            "hash": self.hash_to_check,
            "enckey": sent_key,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            time.sleep(3)
            os._exit(1)

        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                time.sleep(3)
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        
        if json["newSession"]:
            time.sleep(0.1)

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "register",
            "username": user,
            "pass": password,
            "key": license,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print(json["message"])
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()

        post_data = {
            "type": "upgrade",
            "username": user,
            "key": license,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print(json["message"])
            print("Please restart program and login")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "login",
            "username": user,
            "pass": password,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print(json["message"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "type": "license",
            "key": key,
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print(json["message"])
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def var(self, name):
        self.checkinit()

        post_data = {
            "type": "var",
            "varid": name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()

        post_data = {
            "type": "getvar",
            "var": var_name,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()

        post_data = {
            "type": "setvar",
            "var": var_name,
            "data": var_data,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def ban(self):
        self.checkinit()

        post_data = {
            "type": "ban",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()

        post_data = {
            "type": "file",
            "fileid": fileid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()

        post_data = {
            "type": "webhook",
            "webid": webid,
            "params": param,
            "body": body,
            "conttype": conttype,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

    def check(self):
        self.checkinit()

        post_data = {
            "type": "check",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()

        post_data = {
            "type": "checkblacklist",
            "hwid": hwid,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }
        response = self.__do_request(post_data)

        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()

        post_data = {
            "type": "log",
            "pcuser": os.getenv('username'),
            "message": message,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()

        post_data = {
            "type": "fetchOnline",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None
            else:
                return json["users"]
        else:
            return None
            
    def fetchStats(self):
        self.checkinit()

        post_data = {
            "type": "fetchStats",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_app_data(json["appinfo"])
            
    def chatGet(self, channel):
        self.checkinit()

        post_data = {
            "type": "chatget",
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()

        post_data = {
            "type": "chatsend",
            "message": message,
            "channel": channel,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()

        post_data = {
            "type": "changeUsername",
            "newUsername": username,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully changed username")
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)  

    def logout(self):
        self.checkinit()

        post_data = {
            "type": "logout",
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid
        }

        response = self.__do_request(post_data)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully logged out")
            time.sleep(3)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(3)
            os._exit(1)         
            
    def __do_request(self, post_data):
        try:
            response = requests.post(
                "https://keyauth.win/api/1.2/", data=post_data, timeout=10
            )
            
            key = self.secret if post_data["type"] == "init" else self.enckey
            if post_data["type"] == "log": return response.text
                        
            client_computed = hmac.new(key.encode('utf-8'), response.text.encode('utf-8'), hashlib.sha256).hexdigest()
            
            signature = response.headers["signature"]

            if not os.path.exists("C:\\ProgramData\\KeyAuth"):
                os.makedirs("C:\\ProgramData\\KeyAuth")
                os.makedirs("C:\\ProgramData\\KeyAuth\\Debug")

            exe_name = os.path.basename(__file__)
            if not os.path.exists(f"C:\\ProgramData\\KeyAuth\\Debug\\{exe_name}"):
                os.makedirs(f"C:\\ProgramData\\KeyAuth\\Debug\\{exe_name}")

            with open(f"C:\\ProgramData\\KeyAuth\\Debug\\{exe_name}\\log.txt", "a") as log_file:
                if len(response.text) <= 200:
                    tampered = not hmac.compare_digest(client_computed, signature)
                    execution_time = time.strftime("%I:%M %p | %m/%d/%Y")
                    log_file.write(f"\n{execution_time} | {post_data['type']} \nResponse: {response.text}\n Was response tampered with? {tampered}\n")
            
            if not hmac.compare_digest(client_computed, signature):
                print("Signature checksum failed. Request was tampered with or session ended most likely.")
                print("Response: " + response.text)
                time.sleep(3)
                os._exit(1) 
            
            return response.text
        except requests.exceptions.Timeout:
            print("Request timed out. Server is probably down/slow at the moment")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"] or "N/A"
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
            '''
            cmd = subprocess.Popen(
                "wmic useraccount where name='%username%' get sid",
                stdout=subprocess.PIPE,
                shell=True,
            )

            (suppost_sid, error) = cmd.communicate()

            suppost_sid = suppost_sid.split(b"\n")[1].strip()

            return suppost_sid.decode()

            ^^ HOW TO DO IT USING WMIC
            '''
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid


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
        main_layout = QVBoxLayout()

        # KeyAuth giriş alanları
        auth_group = QGroupBox("Lisans Girişi")
        auth_layout = QFormLayout()

        self.username_input = QLineEdit()
        auth_layout.addRow("Kullanıcı Adı:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        auth_layout.addRow("Şifre:", self.password_input)

        self.license_input = QLineEdit()
        self.license_input.setVisible(False)
        auth_layout.addRow("Lisans Anahtarı:", self.license_input)

        button_layout = QHBoxLayout()
        login_button = QPushButton("Giriş")
        login_button.clicked.connect(self.login)
        button_layout.addWidget(login_button)

        register_button = QPushButton("Kayıt Ol")
        register_button.clicked.connect(self.show_register_fields)
        button_layout.addWidget(register_button)

        self.submit_button = QPushButton("Gönder")
        self.submit_button.clicked.connect(self.submit)
        self.submit_button.setVisible(False)
        button_layout.addWidget(self.submit_button)

        auth_layout.addRow(button_layout)
        auth_group.setLayout(auth_layout)
        main_layout.addWidget(auth_group)

        self.info_label = QLabel()
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setFont(QFont("Arial", 10))
        main_layout.addWidget(self.info_label)

        # Circle Generator alanları
        self.circle_group = QGroupBox("Google Maps Backlink-Pin Generator")
        self.circle_group.setVisible(False)
        circle_layout = QFormLayout()

        self.name_input = QLineEdit()
        circle_layout.addRow("Name:", self.name_input)

        self.description_input = QLineEdit()
        circle_layout.addRow("Description:", self.description_input)

        self.center_lat_input = QLineEdit()
        circle_layout.addRow("Merkez Latitude:", self.center_lat_input)

        self.center_long_input = QLineEdit()
        circle_layout.addRow("Merkez Longitude:", self.center_long_input)

        self.radius_input = QLineEdit()
        circle_layout.addRow("Yarıçap (km):", self.radius_input)

        self.num_points_input = QLineEdit()
        circle_layout.addRow("Koordinat Sayısı:", self.num_points_input)

        self.keywords_input = QLineEdit()
        circle_layout.addRow("Keywords (virgülle ayırın):", self.keywords_input)

        self.website_input = QLineEdit()
        circle_layout.addRow("Website:", self.website_input)

        self.phone_number_input = QLineEdit()
        circle_layout.addRow("Phone Number:", self.phone_number_input)

        # Koordinat oluşturma modu seçimi
        self.coord_mode = QComboBox()
        self.coord_mode.addItem("Çemberleri Oluştur")
        self.coord_mode.addItem("Dairenin İçini Doldur")
        circle_layout.addRow("Koordinat Oluşturma Modu:", self.coord_mode)

        self.generate_button = QPushButton("Pinleri Yarat")
        self.generate_button.clicked.connect(self.generate_coordinates)
        circle_layout.addRow(self.generate_button)

        self.circle_group.setLayout(circle_layout)
        main_layout.addWidget(self.circle_group)

        self.setLayout(main_layout)
        self.setWindowTitle('Welt Agency Google Maps Backlink-Pin Generator')
        self.setGeometry(300, 300, 500, 600)
        self.setWindowIcon(QIcon('icon.png'))  # Uygulamanız için bir ikon ekleyin

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
            QMessageBox.information(self, "Başarılı", "Giriş başarılı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Giriş başarısız: {str(e)}")

    def show_register_fields(self):
        self.license_input.setVisible(True)
        self.submit_button.setText("Kayıt Ol")
        self.submit_button.setVisible(True)

    def submit(self):
        if self.submit_button.text() == "Kayıt Ol":
            self.register()
        else:
            self.login()

    def register(self):
        user = self.username_input.text()
        password = self.password_input.text()
        license = self.license_input.text()
        try:
            self.keyauthapp.register(user, password, license)
            self.show_user_info()
            self.show_circle_generator()
            QMessageBox.information(self, "Başarılı", "Kayıt başarılı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Kayıt başarısız: {str(e)}")

    def upgrade(self):
        user = self.username_input.text()
        license = self.license_input.text()
        try:
            self.keyauthapp.upgrade(user, license)
            self.show_user_info()
            self.show_circle_generator()
            QMessageBox.information(self, "Başarılı", "Yükseltme başarılı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Yükseltme başarısız: {str(e)}")

    def verify_license(self):
        key = self.license_input.text()
        try:
            self.keyauthapp.license(key)
            self.show_user_info()
            self.show_circle_generator()
            QMessageBox.information(self, "Başarılı", "Lisans doğrulama başarılı!")
        except Exception as e:
            QMessageBox.warning(self, "Hata", f"Lisans doğrulama başarısız: {str(e)}")

    def show_user_info(self):
        info = f"Kullanıcı Adı: {self.keyauthapp.user_data.username}\n"
        info += f"IP Adresi: {self.keyauthapp.user_data.ip}\n"
        info += f"Hardware-Id: {self.keyauthapp.user_data.hwid}\n"
        info += f"Oluşturulma Tarihi: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Son Giriş: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Bitiş Tarihi: {datetime.utcfromtimestamp(int(self.keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.info_label.setText(info)

    def show_circle_generator(self):
        self.circle_group.setVisible(True)

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
            mode = self.coord_mode.currentText()

            if mode == "Çemberleri Oluştur":
                coordinates = self.generate_concentric_circles(center_lat, center_long, radius, num_points)
            else:  # Dairenin İçini Doldur
                coordinates = self.generate_random_coordinates(center_lat, center_long, radius, num_points)

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

    def generate_random_coordinates(self, center_lat, center_long, radius, num_points):
        points = []
        for _ in range(num_points):
            angle = random.uniform(0, 360)
            distance_from_center = random.uniform(0, radius)
            destination = geodesic(kilometers=distance_from_center).destination((center_lat, center_long), angle)
            points.append((destination.latitude, destination.longitude))
        return points

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = KeyAuthCircleApp()
    ex.show()
    sys.exit(app.exec_())
