import os
import sys
import zipfile
import base64
import hashlib
import secrets
import string
import webbrowser
from io import BytesIO
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame,
    QPushButton, QLabel, QFileDialog, QLineEdit, QTextEdit, QComboBox,
    QSpinBox, QCheckBox, QMessageBox, QStackedWidget, QProgressBar
)

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

APP_NAME = "SecureCore Suite"
APP_VERSION = "1.0.0"
APP_AUTHOR  = "©Thorsten Bylicki | ©BYLICKILABS"
GITHUB_URL = "https://github.com/bylickilabs"

I18N = {
    "de": {
        "app_title": f"{APP_NAME} v{APP_VERSION} - {APP_AUTHOR}",
        "nav_dashboard": "Dashboard",
        "nav_encrypt": "Verschlüsseln",
        "nav_decrypt": "Entschlüsseln",
        "nav_hash": "Hashing",
        "nav_password": "Passwörter",
        "nav_about": "Info",
        "nav_github": "GitHub",
        "lang_toggle": "DE / EN",
        "status_ready": "Bereit.",
        "missing_crypto": "Das Paket 'cryptography' ist nicht installiert.",
        "encrypt_file_title": "Datei verschlüsseln",
        "decrypt_file_title": "Datei entschlüsseln",
        "encrypt_dir_title": "Verzeichnis als Archiv verschlüsseln",
        "decrypt_arc_title": "Archiv entschlüsseln",
        "select_file": "Datei wählen",
        "select_dir": "Verzeichnis wählen",
        "select_arc": "Archiv wählen",
        "browse": "Durchsuchen",
        "password": "Passwort",
        "password_confirm": "Passwort wiederholen",
        "encrypt_btn": "Verschlüsseln",
        "decrypt_btn": "Entschlüsseln",
        "hash_file_label": "Datei für Hash wählen",
        "hash_algo": "Algorithmus",
        "hash_compute": "Hash berechnen",
        "hash_result": "Hash-Wert",
        "pw_length": "Länge",
        "pw_upper": "Großbuchstaben",
        "pw_lower": "Kleinbuchstaben",
        "pw_digits": "Ziffern",
        "pw_symbols": "Sonderzeichen",
        "pw_generate": "Passwort generieren",
        "pw_strength": "Passwortstärke",
        "pw_strength_weak": "Schwach",
        "pw_strength_moderate": "Mittel",
        "pw_strength_strong": "Stark",
        "pw_strength_very_strong": "Sehr stark",
        "info": "Information",
        "error": "Fehler",
        "ok": "OK",
        "file_missing": "Keine gültige Datei gewählt.",
        "dir_missing": "Kein gültiges Verzeichnis gewählt.",
        "arc_missing": "Kein gültiges Archiv gewählt.",
        "pw_missing": "Passwort erforderlich.",
        "pw_mismatch": "Passwörter stimmen nicht überein.",
        "enc_success": "Verschlüsselung erfolgreich abgeschlossen.",
        "dec_success": "Entschlüsselung erfolgreich abgeschlossen.",
        "dec_failed_pw": "Entschlüsselung fehlgeschlagen. Passwort prüfen.",
        "select_out_dir": "Zielverzeichnis wählen",
        "dashboard_title": "SecureCore Suite - Powered by BYICKILABS",
        "dashboard_sub": "Professionelle Desktop-Lösung für Verschlüsselung, Integrität und Passwortsicherheit.",
        "about_text": (
            f"{APP_NAME} ist eine lokal ausgeführte Sicherheits-Suite für:\n"
            "- Verschlüsselung von Dateien und Verzeichnissen\n"
            "- Integritätsprüfungen (Hashing)\n"
            "- Passwort-Erzeugung und -Bewertung\n\n"
            "Alle Operationen erfolgen lokal. Kein Tracking, kein Cloud-Zwang.\n"
            "Hinweis: Für hochkritische Umgebungen sind formell geprüfte Lösungen zu verwenden."
        ),
        "github_open": "GitHub-Profil öffnen"
    },
    "en": {
        "app_title": f"{APP_NAME} v{APP_VERSION} - {APP_AUTHOR}",
        "nav_dashboard": "Dashboard",
        "nav_encrypt": "Encrypt",
        "nav_decrypt": "Decrypt",
        "nav_hash": "Hashing",
        "nav_password": "Passwords",
        "nav_about": "About",
        "nav_github": "GitHub",
        "lang_toggle": "DE / EN",
        "status_ready": "Ready.",
        "missing_crypto": "Package 'cryptography' is not installed.",
        "encrypt_file_title": "Encrypt File",
        "decrypt_file_title": "Decrypt File",
        "encrypt_dir_title": "Encrypt Directory as Archive",
        "decrypt_arc_title": "Decrypt Archive",
        "select_file": "Select file",
        "select_dir": "Select directory",
        "select_arc": "Select archive",
        "browse": "Browse",
        "password": "Password",
        "password_confirm": "Confirm password",
        "encrypt_btn": "Encrypt",
        "decrypt_btn": "Decrypt",
        "hash_file_label": "Select file for hash",
        "hash_algo": "Algorithm",
        "hash_compute": "Compute hash",
        "hash_result": "Hash value",
        "pw_length": "Length",
        "pw_upper": "Uppercase letters",
        "pw_lower": "Lowercase letters",
        "pw_digits": "Digits",
        "pw_symbols": "Special characters",
        "pw_generate": "Generate password",
        "pw_strength": "Password strength",
        "pw_strength_weak": "Weak",
        "pw_strength_moderate": "Moderate",
        "pw_strength_strong": "Strong",
        "pw_strength_very_strong": "Very strong",
        "info": "Information",
        "error": "Error",
        "ok": "OK",
        "file_missing": "No valid file selected.",
        "dir_missing": "No valid directory selected.",
        "arc_missing": "No valid archive selected.",
        "pw_missing": "Password required.",
        "pw_mismatch": "Passwords do not match.",
        "enc_success": "Encryption completed successfully.",
        "dec_success": "Decryption completed successfully.",
        "dec_failed_pw": "Decryption failed. Please verify the password.",
        "select_out_dir": "Select output directory",
        "dashboard_title": "SecureCore Suite - Powered by BYICKILABS",
        "dashboard_sub": "Professional desktop solution for encryption, integrity and password security.",
        "about_text": (
            f"{APP_NAME} is a local security suite for:\n"
            "- File and directory encryption\n"
            "- Integrity checks (hashing)\n"
            "- Password generation and evaluation\n\n"
            "All operations run locally. No tracking, no forced cloud.\n"
            "For highly critical environments, use formally audited solutions."
        ),
        "github_open": "Open GitHub profile"
    }
}

@dataclass
class PasswordStrength:
    score: int
    label_key: str

class CryptoEngine:
    SALT_SIZE = 16
    ITERATIONS = 200_000

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography not available")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CryptoEngine.ITERATIONS,
        )
        key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt_bytes(data: bytes, password: str) -> bytes:
        salt = secrets.token_bytes(CryptoEngine.SALT_SIZE)
        key = CryptoEngine._derive_key(password, salt)
        f = Fernet(key)
        token = f.encrypt(data)
        return salt + token

    @staticmethod
    def decrypt_bytes(data: bytes, password: str) -> bytes:
        salt = data[:CryptoEngine.SALT_SIZE]
        token = data[CryptoEngine.SALT_SIZE:]
        key = CryptoEngine._derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(token)

    @staticmethod
    def encrypt_file(in_path: str, out_path: str, password: str):
        with open(in_path, "rb") as f:
            plaintext = f.read()
        ciphertext = CryptoEngine.encrypt_bytes(plaintext, password)
        with open(out_path, "wb") as f:
            f.write(ciphertext)

    @staticmethod
    def decrypt_file(in_path: str, out_path: str, password: str):
        with open(in_path, "rb") as f:
            ciphertext = f.read()
        try:
            plaintext = CryptoEngine.decrypt_bytes(ciphertext, password)
        except InvalidToken as e:
            raise ValueError("invalid_password") from e
        with open(out_path, "wb") as f:
            f.write(plaintext)

    @staticmethod
    def encrypt_directory_as_archive(dir_path: str, out_path: str, password: str):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(dir_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=dir_path)
                    zipf.write(full_path, arcname)
        zip_bytes = buffer.getvalue()
        enc = CryptoEngine.encrypt_bytes(zip_bytes, password)
        with open(out_path, "wb") as f:
            f.write(enc)

    @staticmethod
    def decrypt_archive(enc_path: str, out_dir: str, password: str):
        with open(enc_path, "rb") as f:
            enc = f.read()
        try:
            zip_bytes = CryptoEngine.decrypt_bytes(enc, password)
        except InvalidToken as e:
            raise ValueError("invalid_password") from e
        buffer = BytesIO(zip_bytes)
        with zipfile.ZipFile(buffer, "r") as zipf:
            zipf.extractall(out_dir)


class HashUtils:
    ALGORITHMS = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }

    @staticmethod
    def file_hash(path: str, algo: str) -> str:
        if algo not in HashUtils.ALGORITHMS:
            raise ValueError("Unsupported algorithm")
        h = HashUtils.ALGORITHMS[algo]()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


class PasswordUtils:
    @staticmethod
    def generate(length=16, upper=True, lower=True, digits=True, symbols=True) -> str:
        charset = ""
        if upper:
            charset += string.ascii_uppercase
        if lower:
            charset += string.ascii_lowercase
        if digits:
            charset += string.digits
        if symbols:
            charset += "!@$%&*?-_#"
        if not charset:
            charset = string.ascii_letters + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))

    @staticmethod
    def strength(password: str) -> PasswordStrength:
        length = len(password)
        upper = any(c.isupper() for c in password)
        lower = any(c.islower() for c in password)
        digits = any(c.isdigit() for c in password)
        symbols = any(c in "!@$%&*?-_#" for c in password)

        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
        types = sum([upper, lower, digits, symbols])
        score += types

        if score <= 2:
            label_key = "pw_strength_weak"
        elif score == 3:
            label_key = "pw_strength_moderate"
        elif score == 4:
            label_key = "pw_strength_strong"
        else:
            label_key = "pw_strength_very_strong"

        return PasswordStrength(score=min(score, 5), label_key=label_key)

class DashboardPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        self.title = QLabel()
        self.sub = QLabel()
        self.sub.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        self.title.setObjectName("Title")
        self.sub.setObjectName("SubTitle")
        layout.addWidget(self.title)
        layout.addWidget(self.sub)
        layout.addStretch(1)
        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.title.setText(t["dashboard_title"])
        self.sub.setText(t["dashboard_sub"])


class EncryptPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main

        self.file_path = QLineEdit()
        self.dir_path = QLineEdit()
        self.pw_file = QLineEdit()
        self.pw_file2 = QLineEdit()
        self.pw_dir = QLineEdit()
        self.progress = QProgressBar()
        self.progress.setMaximum(0)
        self.progress.setVisible(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        self.file_title = QLabel()
        self.file_title.setObjectName("SectionTitle")
        layout.addWidget(self.file_title)

        row1 = QHBoxLayout()
        row1.addWidget(self.file_path)
        self.btn_file_browse = QPushButton()
        self.btn_file_browse.clicked.connect(self.browse_file)
        row1.addWidget(self.btn_file_browse)
        layout.addLayout(row1)

        pw_row = QHBoxLayout()
        self.pw_file.setEchoMode(QLineEdit.Password)
        self.pw_file2.setEchoMode(QLineEdit.Password)
        pw_row.addWidget(self.pw_file)
        pw_row.addWidget(self.pw_file2)
        layout.addLayout(pw_row)

        btn_row = QHBoxLayout()
        self.btn_encrypt = QPushButton()
        self.btn_decrypt = QPushButton()
        self.btn_encrypt.clicked.connect(self.encrypt_file)
        self.btn_decrypt.clicked.connect(self.decrypt_file)
        btn_row.addWidget(self.btn_encrypt)
        btn_row.addWidget(self.btn_decrypt)
        layout.addLayout(btn_row)

        self.dir_title = QLabel()
        self.dir_title.setObjectName("SectionTitle")
        layout.addWidget(self.dir_title)

        dir_row = QHBoxLayout()
        dir_row.addWidget(self.dir_path)
        self.btn_dir_browse = QPushButton()
        self.btn_dir_browse.clicked.connect(self.browse_dir)
        dir_row.addWidget(self.btn_dir_browse)
        layout.addLayout(dir_row)

        self.pw_dir.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pw_dir)

        self.btn_encrypt_dir = QPushButton()
        self.btn_encrypt_dir.clicked.connect(self.encrypt_dir)
        layout.addWidget(self.btn_encrypt_dir, alignment=Qt.AlignRight)

        layout.addWidget(self.progress)
        layout.addStretch(1)

        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.file_title.setText(t["encrypt_file_title"])
        self.dir_title.setText(t["encrypt_dir_title"])
        self.btn_file_browse.setText(t["browse"])
        self.btn_dir_browse.setText(t["select_dir"])
        self.pw_file.setPlaceholderText(t["password"])
        self.pw_file2.setPlaceholderText(t["password_confirm"])
        self.pw_dir.setPlaceholderText(t["password"])
        self.btn_encrypt.setText(t["encrypt_btn"])
        self.btn_decrypt.setText(t["decrypt_btn"])
        self.btn_encrypt_dir.setText(t["encrypt_dir_title"])

    def show_busy(self, on: bool):
        self.progress.setVisible(on)

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, self.main.tr["select_file"])
        if path:
            self.file_path.setText(path)

    def browse_dir(self):
        path = QFileDialog.getExistingDirectory(self, self.main.tr["select_dir"])
        if path:
            self.dir_path.setText(path)

    def encrypt_file(self):
        if not CRYPTO_AVAILABLE:
            self.main.error(self.main.tr["missing_crypto"])
            return
        path = self.file_path.text().strip()
        pw = self.pw_file.text()
        pw2 = self.pw_file2.text()
        if not path or not os.path.isfile(path):
            self.main.error(self.main.tr["file_missing"])
            return
        if not pw or not pw2:
            self.main.error(self.main.tr["pw_missing"])
            return
        if pw != pw2:
            self.main.error(self.main.tr["pw_mismatch"])
            return
        out_path = path + ".enc"
        try:
            self.show_busy(True)
            QApplication.processEvents()
            CryptoEngine.encrypt_file(path, out_path, pw)
            self.main.info(self.main.tr["enc_success"])
            self.main.set_status(self.main.tr["enc_success"])
        except Exception as e:
            self.main.error(str(e))
        finally:
            self.show_busy(False)

    def decrypt_file(self):
        if not CRYPTO_AVAILABLE:
            self.main.error(self.main.tr["missing_crypto"])
            return
        path = self.file_path.text().strip()
        pw = self.pw_file.text()
        if not path or not os.path.isfile(path):
            self.main.error(self.main.tr["file_missing"])
            return
        if not pw:
            self.main.error(self.main.tr["pw_missing"])
            return
        if path.endswith(".enc"):
            out_path = path[:-4]
        else:
            out_path = path + ".dec"
        try:
            self.show_busy(True)
            QApplication.processEvents()
            CryptoEngine.decrypt_file(path, out_path, pw)
            self.main.info(self.main.tr["dec_success"])
            self.main.set_status(self.main.tr["dec_success"])
        except ValueError:
            self.main.error(self.main.tr["dec_failed_pw"])
            self.main.set_status(self.main.tr["dec_failed_pw"])
        except Exception as e:
            self.main.error(str(e))
        finally:
            self.show_busy(False)

    def encrypt_dir(self):
        if not CRYPTO_AVAILABLE:
            self.main.error(self.main.tr["missing_crypto"])
            return
        dir_path = self.dir_path.text().strip()
        pw = self.pw_dir.text()
        if not dir_path or not os.path.isdir(dir_path):
            self.main.error(self.main.tr["dir_missing"])
            return
        if not pw:
            self.main.error(self.main.tr["pw_missing"])
            return
        out_path = os.path.abspath(dir_path.rstrip("/\\")) + ".zip.enc"
        try:
            self.show_busy(True)
            QApplication.processEvents()
            CryptoEngine.encrypt_directory_as_archive(dir_path, out_path, pw)
            self.main.info(self.main.tr["enc_success"])
            self.main.set_status(self.main.tr["enc_success"])
        except Exception as e:
            self.main.error(str(e))
        finally:
            self.show_busy(False)

class DecryptArchivePage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main

        self.arc_path = QLineEdit()
        self.pw_arc = QLineEdit()
        self.progress = QProgressBar()
        self.progress.setMaximum(0)
        self.progress.setVisible(False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        self.title = QLabel()
        self.title.setObjectName("SectionTitle")
        layout.addWidget(self.title)

        row = QHBoxLayout()
        row.addWidget(self.arc_path)
        self.btn_browse = QPushButton()
        self.btn_browse.clicked.connect(self.browse_arc)
        row.addWidget(self.btn_browse)
        layout.addLayout(row)

        self.pw_arc.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pw_arc)

        self.btn_decrypt = QPushButton()
        self.btn_decrypt.clicked.connect(self.decrypt_archive)
        layout.addWidget(self.btn_decrypt, alignment=Qt.AlignRight)

        layout.addWidget(self.progress)
        layout.addStretch(1)

        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.title.setText(t["decrypt_arc_title"])
        self.btn_browse.setText(t["browse"])
        self.pw_arc.setPlaceholderText(t["password"])
        self.btn_decrypt.setText(t["decrypt_btn"])

    def show_busy(self, on: bool):
        self.progress.setVisible(on)

    def browse_arc(self):
        path, _ = QFileDialog.getOpenFileName(self, self.main.tr["select_arc"])
        if path:
            self.arc_path.setText(path)

    def decrypt_archive(self):
        if not CRYPTO_AVAILABLE:
            self.main.error(self.main.tr["missing_crypto"])
            return
        arc = self.arc_path.text().strip()
        pw = self.pw_arc.text()
        if not arc or not os.path.isfile(arc):
            self.main.error(self.main.tr["arc_missing"])
            return
        if not pw:
            self.main.error(self.main.tr["pw_missing"])
            return
        out_dir = QFileDialog.getExistingDirectory(self, self.main.tr["select_out_dir"])
        if not out_dir:
            return
        try:
            self.show_busy(True)
            QApplication.processEvents()
            CryptoEngine.decrypt_archive(arc, out_dir, pw)
            self.main.info(self.main.tr["dec_success"])
            self.main.set_status(self.main.tr["dec_success"])
        except ValueError:
            self.main.error(self.main.tr["dec_failed_pw"])
            self.main.set_status(self.main.tr["dec_failed_pw"])
        except Exception as e:
            self.main.error(str(e))
        finally:
            self.show_busy(False)

class HashPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main

        self.file_path = QLineEdit()
        self.algo = QComboBox()
        self.result = QTextEdit()
        self.result.setReadOnly(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        self.title = QLabel()
        self.title.setObjectName("SectionTitle")
        layout.addWidget(self.title)

        row = QHBoxLayout()
        row.addWidget(self.file_path)
        self.btn_browse = QPushButton()
        self.btn_browse.clicked.connect(self.browse_file)
        row.addWidget(self.btn_browse)
        layout.addLayout(row)

        algo_row = QHBoxLayout()
        self.algo_label = QLabel()
        algo_row.addWidget(self.algo_label)
        self.algo.addItems(list(HashUtils.ALGORITHMS.keys()))
        algo_row.addWidget(self.algo)
        self.btn_hash = QPushButton()
        self.btn_hash.clicked.connect(self.compute_hash)
        algo_row.addWidget(self.btn_hash)
        layout.addLayout(algo_row)

        self.result_label = QLabel()
        layout.addWidget(self.result_label)
        layout.addWidget(self.result)

        layout.addStretch(1)
        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.title.setText(t["hash_file_label"])
        self.btn_browse.setText(t["browse"])
        self.algo_label.setText(t["hash_algo"])
        self.btn_hash.setText(t["hash_compute"])
        self.result_label.setText(t["hash_result"])

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, self.main.tr["hash_file_label"])
        if path:
            self.file_path.setText(path)

    def compute_hash(self):
        path = self.file_path.text().strip()
        if not path or not os.path.isfile(path):
            self.main.error(self.main.tr["file_missing"])
            return
        algo = self.algo.currentText()
        try:
            h = HashUtils.file_hash(path, algo)
            self.result.setPlainText(f"{algo}: {h}")
            self.main.set_status("OK")
        except Exception as e:
            self.main.error(str(e))

class PasswordPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main

        self.len_spin = QSpinBox()
        self.len_spin.setRange(8, 64)
        self.len_spin.setValue(16)

        self.cb_upper = QCheckBox()
        self.cb_upper.setChecked(True)
        self.cb_lower = QCheckBox()
        self.cb_lower.setChecked(True)
        self.cb_digits = QCheckBox()
        self.cb_digits.setChecked(True)
        self.cb_symbols = QCheckBox()
        self.cb_symbols.setChecked(True)

        self.output = QLineEdit()
        self.strength_label = QLabel()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(12)

        self.title = QLabel()
        self.title.setObjectName("SectionTitle")
        layout.addWidget(self.title)

        row_len = QHBoxLayout()
        self.len_label = QLabel()
        row_len.addWidget(self.len_label)
        row_len.addWidget(self.len_spin)
        layout.addLayout(row_len)

        row_opts1 = QHBoxLayout()
        row_opts2 = QHBoxLayout()
        row_opts1.addWidget(self.cb_upper)
        row_opts1.addWidget(self.cb_lower)
        row_opts2.addWidget(self.cb_digits)
        row_opts2.addWidget(self.cb_symbols)
        layout.addLayout(row_opts1)
        layout.addLayout(row_opts2)

        self.btn_gen = QPushButton()
        self.btn_gen.clicked.connect(self.generate)
        layout.addWidget(self.btn_gen)

        layout.addWidget(self.output)
        layout.addWidget(self.strength_label)

        layout.addStretch(1)
        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.title.setText(t["nav_password"])
        self.len_label.setText(t["pw_length"])
        self.cb_upper.setText(t["pw_upper"])
        self.cb_lower.setText(t["pw_lower"])
        self.cb_digits.setText(t["pw_digits"])
        self.cb_symbols.setText(t["pw_symbols"])
        self.btn_gen.setText(t["pw_generate"])
        self.strength_label.setText(f"{t['pw_strength']}: -")

    def generate(self):
        t = self.main.tr
        pw = PasswordUtils.generate(
            length=self.len_spin.value(),
            upper=self.cb_upper.isChecked(),
            lower=self.cb_lower.isChecked(),
            digits=self.cb_digits.isChecked(),
            symbols=self.cb_symbols.isChecked(),
        )
        self.output.setText(pw)
        s = PasswordUtils.strength(pw)
        label = t[s.label_key]
        self.strength_label.setText(f"{t['pw_strength']}: {label} ({s.score}/5)")
        self.main.set_status("OK")

class AboutPage(QWidget):
    def __init__(self, main):
        super().__init__()
        self.main = main
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(15)

        self.title = QLabel(APP_NAME)
        self.title.setObjectName("Title")
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.github_btn = QPushButton()
        self.github_btn.clicked.connect(self.open_github)

        layout.addWidget(self.title)
        layout.addWidget(self.text)
        layout.addWidget(self.github_btn, alignment=Qt.AlignLeft)
        layout.addStretch(1)
        self.update_texts()

    def update_texts(self):
        t = self.main.tr
        self.text.setText(t["about_text"])
        self.github_btn.setText(t["github_open"])

    def open_github(self):
        webbrowser.open(GITHUB_URL)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.lang = "de"
        self.tr = I18N[self.lang]

        self.setWindowTitle(self.tr["app_title"])
        self.resize(1150, 720)

        self._apply_style()

        central = QWidget()
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(230)
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(18, 18, 18, 18)
        sb_layout.setSpacing(10)

        self.logo_label = QLabel("🛡️ SecureCore X")
        self.logo_label.setObjectName("Logo")
        sb_layout.addWidget(self.logo_label)

        self.btn_dash = QPushButton()
        self.btn_enc = QPushButton()
        self.btn_dec = QPushButton()
        self.btn_hash = QPushButton()
        self.btn_pw = QPushButton()
        self.btn_about = QPushButton()
        self.btn_github = QPushButton()

        for b in [self.btn_dash, self.btn_enc, self.btn_dec, self.btn_hash, self.btn_pw, self.btn_about, self.btn_github]:
            b.setObjectName("MenuButton")
            sb_layout.addWidget(b)

        sb_layout.addStretch(1)

        self.lang_btn = QPushButton()
        self.lang_btn.setObjectName("LangButton")
        self.lang_btn.clicked.connect(self.toggle_lang)
        sb_layout.addWidget(self.lang_btn)

        root_layout.addWidget(self.sidebar)

        content_frame = QFrame()
        content_frame.setObjectName("Content")
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(18, 18, 18, 8)
        content_layout.setSpacing(8)

        self.header_label = QLabel(APP_NAME)
        self.header_label.setObjectName("HeaderTitle")
        content_layout.addWidget(self.header_label)

        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack, 1)

        self.status_bar = QLabel()
        self.status_bar.setObjectName("StatusBar")
        content_layout.addWidget(self.status_bar)

        root_layout.addWidget(content_frame, 1)
        self.setCentralWidget(central)

        self.page_dashboard = DashboardPage(self)
        self.page_encrypt = EncryptPage(self)
        self.page_dec_arc = DecryptArchivePage(self)
        self.page_hash = HashPage(self)
        self.page_pw = PasswordPage(self)
        self.page_about = AboutPage(self)

        self.stack.addWidget(self.page_dashboard)
        self.stack.addWidget(self.page_encrypt)
        self.stack.addWidget(self.page_dec_arc)
        self.stack.addWidget(self.page_hash)
        self.stack.addWidget(self.page_pw)
        self.stack.addWidget(self.page_about)

        self.btn_dash.clicked.connect(lambda: self.switch_page(0))
        self.btn_enc.clicked.connect(lambda: self.switch_page(1))
        self.btn_dec.clicked.connect(lambda: self.switch_page(2))
        self.btn_hash.clicked.connect(lambda: self.switch_page(3))
        self.btn_pw.clicked.connect(lambda: self.switch_page(4))
        self.btn_about.clicked.connect(lambda: self.switch_page(5))
        self.btn_github.clicked.connect(self.open_github)

        self.update_texts()
        self.set_status(self.tr["status_ready"])

    def _apply_style(self):
        self.setStyleSheet("""
        QMainWindow {
            background-color: #181A1B;
            color: #EEEEEE;
            font-family: "Segoe UI", sans-serif;
            font-size: 10.5pt;
        }
        #Sidebar {
            background-color: #1F2123;
            border-right: 1px solid #303234;
        }
        #Logo {
            font-size: 16pt;
            font-weight: 600;
            color: #00FFFF;
            margin-bottom: 10px;
        }
        #Content {
            background-color: #181A1B;
        }
        #HeaderTitle {
            font-size: 14pt;
            font-weight: 600;
            color: #FF00FF;
            margin-bottom: 4px;
        }
        #Title {
            font-size: 18pt;
            font-weight: 600;
            color: #FF00FF;
            margin-bottom: 10px;
        }
        #SubTitle {
            font-size: 10.5pt;
            color: #CCCCCC;
        }
        #SectionTitle {
            font-size: 11.5pt;
            font-weight: 500;
            color: #00FFFF;
        }
        #MenuButton, #LangButton {
            background-color: #26282A;
            color: #DDDDDD;
            border: 1px solid #333333;
            border-radius: 6px;
            padding: 7px;
            text-align: left;
        }
        #MenuButton:hover, #LangButton:hover {
            background-color: #33363A;
            color: #00FFFF;
            border-color: #00FFFF;
        }
        QPushButton {
            font-family: "Segoe UI";
        }
        QLineEdit, QTextEdit, QComboBox, QSpinBox {
            background-color: #232527;
            color: #EEEEEE;
            border-radius: 4px;
            border: 1px solid #3A3C3E;
            padding: 4px;
        }
        QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
            border: 1px solid #00FFFF;
        }
        QCheckBox {
            color: #DDDDDD;
        }
        #StatusBar {
            background-color: #181A1B;
            color: #AAAAAA;
            padding: 4px 6px;
            border-top: 1px solid #303234;
        }
        QProgressBar {
            border: 1px solid #3A3C3E;
            border-radius: 3px;
            background-color: #202224;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(
                spread:pad, x1:0, y1:0, x2:1, y2:0,
                stop:0 #00FFFF, stop:0.5 #FF00FF, stop:1 #FF66CC
            );
        }
        """)

    def update_texts(self):
        t = self.tr
        self.setWindowTitle(t["app_title"])
        self.header_label.setText(APP_NAME)

        self.btn_dash.setText("🏠 " + t["nav_dashboard"])
        self.btn_enc.setText("🔒 " + t["nav_encrypt"])
        self.btn_dec.setText("🗂️ " + t["nav_decrypt"])
        self.btn_hash.setText("🧮 " + t["nav_hash"])
        self.btn_pw.setText("🔑 " + t["nav_password"])
        self.btn_about.setText("ℹ️ " + t["nav_about"])
        self.btn_github.setText("🌐 " + t["nav_github"])
        self.lang_btn.setText(t["lang_toggle"])

        self.page_dashboard.update_texts()
        self.page_encrypt.update_texts()
        self.page_dec_arc.update_texts()
        self.page_hash.update_texts()
        self.page_pw.update_texts()
        self.page_about.update_texts()

    def switch_page(self, index: int):
        self.stack.setCurrentIndex(index)
        self.set_status(self.tr["status_ready"])

    def toggle_lang(self):
        self.lang = "en" if self.lang == "de" else "de"
        self.tr = I18N[self.lang]
        self.update_texts()
        self.set_status(self.tr["status_ready"])

    def set_status(self, text: str):
        self.status_bar.setText(f"◉ {text}")

    def info(self, msg: str):
        QMessageBox.information(self, self.tr["info"], msg)

    def error(self, msg: str):
        QMessageBox.critical(self, self.tr["error"], msg)

    def open_github(self):
        webbrowser.open(GITHUB_URL)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()