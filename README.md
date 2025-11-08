# 🛡️ SecureCore Suite X

**Multilinguale Desktop-Sicherheitsanwendung für Datei-, Verzeichnis- und Archivverschlüsselung, Hash-Prüfungen und Passwortverwaltung.**

|<img width="1280" height="640" alt="securecore" src="https://github.com/user-attachments/assets/78adf9f6-3187-4cb4-9871-10e8a25f501b" />|
|---|

---

## 📖 Übersicht | Overview

SecureCore Suite X ist eine vollständig lokal ausgeführte Sicherheitsanwendung mit moderner Benutzeroberfläche auf Basis von **PySide6 (Qt)**.
Sie kombiniert **Kryptografie, Hashing, Passwortanalyse** und **Mehrsprachigkeit (DE/EN)** in einem performanten, professionellen Interface.
Alle Operationen laufen **offline**, ohne Cloud oder Telemetrie.

---

## ⚙️ Systemanforderungen | System Requirements

| Komponente | Version / Empfehlung |
|-------------|----------------------|
| **Python** | ≥ **3.10** (empfohlen: Python 3.11) |
| **Betriebssystem** | Windows 10/11, macOS 12+, Linux (Ubuntu 22.04+) |
| **RAM** | ≥ 4 GB |
| **Festplatte** | 200 MB freier Speicherplatz |
| **Internetverbindung** | Nur für Paketinstallation (nicht für die Nutzung) |

---

## 🧰 Benötigte Abhängigkeiten | Required Dependencies

| Paket | Beschreibung | Installationsquelle |
|-------|----------------|--------------------|
| **PySide6** | Qt6 GUI-Framework für moderne Desktop-Oberflächen | [PyPI – PySide6](https://pypi.org/project/PySide6/) |
| **cryptography** | Kryptografie-Framework (Fernet, PBKDF2-HMAC, SHA256) | [PyPI – cryptography](https://pypi.org/project/cryptography/) |

Optional:
| Paket | Beschreibung |
|-------|---------------|
| **hashlib** | (In Python integriert) für Hash-Funktionen |
| **base64**, **zipfile**, **secrets**, **string**, **os**, **io** | Standardbibliotheken (bereits in Python enthalten) |

---

## 📦 Installation

### 1️⃣ Python installieren

Lade die neueste Python-Version herunter:

🔗 **[https://www.python.org/downloads/](https://www.python.org/downloads/)**

Achte bei der Installation auf „Add Python to PATH“.  
Prüfe anschließend:
```bash
python --version
```
> Erwartete Ausgabe: `Python 3.11.x`

---

### 2️⃣ Abhängigkeiten installieren

Virtuelle Umgebung erstellen (empfohlen):
```bash
python -m venv venv
```
Aktivieren:
- **Windows:** `venv\Scripts\activate`
- **Linux/macOS:** `source venv/bin/activate`

Installation:
```bash
pip install -r requirements.txt
```
oder manuell:
```bash
pip install PySide6 cryptography
```

---

### 3️⃣ Anwendung starten
```bash
python securecore_suite_x.py
```

---

## 🧾 requirements.txt
```
PySide6>=6.6.0
cryptography>=43.0.0
```

---

## 🧩 Features Overview

### 🔒 Verschlüsselung & Entschlüsselung
- Symmetrische Verschlüsselung (AES-ähnlich mit Fernet)
- PBKDF2-HMAC-SHA256 Schlüsselableitung mit Salt
- Fortschrittsbalken & Statusmeldungen

### 🗂️ Archiv-Management
- ZIP-Kompression & -Dekompression integriert
- Passwortgeschützte Archive

### 🧮 Hashing
- MD5, SHA1, SHA256, SHA512

### 🔑 Passwortgenerator
- Dynamische Stärkeanzeige (0–5 Stufen)
- Einstellbare Zeichen und Länge

### 🌐 Mehrsprachige Oberfläche
- Umschaltbar (DE / EN)

### 🔗 GitHub
- Direktlink: [BYLICKILABS auf GitHub](https://github.com/bylickilabs)

---

## 🧠 Sicherheitshinweis | Security Notice

> SecureCore Suite X ist ein lokal ausführbares Tool zur Demonstration moderner Kryptografie.
> Keine Cloud, kein Tracking. Für kritische Umgebungen sollten geprüfte Systeme eingesetzt werden.

---

## 🧑‍💻 Entwickler / Developer

**BYLICKILABS**  
🔗 [https://github.com/bylickilabs](https://github.com/bylickilabs)  
📧 bylicki@mail.de  

© 2025 BYLICKILABS & Co. KG — All rights reserved.

---

## 🧭 Versionierung / Versioning

| Komponente | Version |
|-------------|----------|
| **SecureCore Suite X** | 1.0.0 |
| **Build** | 2025-11-08 |
| **Python** | 3.10 – 3.12 |
| **Qt (PySide6)** | ≥ 6.6.0 |
| **cryptography** | ≥ 43.0.0 |
