📌 Project Overview

Standard QR codes store data in plain text, which makes sensitive information easy to read by any scanner. This project solves that problem by implementing AES-256 encryption before encoding data into a QR code.

Only users with the correct cryptographic key can decrypt and read the original message.

✨ Key Features

🔒 AES-256 encryption (CBC mode)

🔑 Secure key handling from key.txt

🔄 Random IV for every encryption

📷 High error-correction QR codes

🖥️ Desktop GUI using Tkinter

💾 Automatic QR image saving with timestamps

🏗️ System Architecture

The system uses a modular design, separating cryptographic logic from the GUI.

Workflow:

User enters text via GUI

Data is encrypted using AES-256-CBC

Encrypted data is Base64 encoded

Encoded data is converted into a QR image

QR image is saved locally

🧪 Cryptographic Details
Component	Description
Algorithm	AES-256
Mode	CBC (Cipher Block Chaining)
Key Size	32 bytes
IV	16 bytes (random per encryption)
Encoding	Base64
🛠️ Technologies Used

Python 3

Tkinter – Desktop GUI

PyCryptodome – Encryption & decryption

qrcode – QR generation

pyzbar – QR decoding

Pillow (PIL) – Image handling

📦 Installation
Requirements

Python 3.8+

pip

Install Dependencies
pip install qrcode[pil] pycryptodome pyzbar

▶️ Running the Application
python main_app.py


On first launch, the system automatically creates key.txt with a default AES key.

📖 Usage Guide
🔐 Generate Encrypted QR Code

Enter text in the input box

Keep Enable AES Encryption checked

Click Generate & Save Directly

QR image is saved in generated_qrs/

🔓 Decrypt QR Code

Click Select QR Image

Choose a QR file from generated_qrs/

Decrypted message appears in the output box

🧾 Example

Input: Secret Password 123

Generated File: QR_ENCRYPTED_YYYYMMDD_HHMMSS.png

Payload: Base64-encoded encrypted data

📁 Project Structure
├── main_app.py
├── key.txt
├── generated_qrs/
├── README.md

⚠️ Security Notes

QR content cannot be decrypted without the key

Unique IV prevents ciphertext pattern reuse

High QR error correction improves reliability

🚀 Future Improvements

Password-based key derivation (PBKDF2)

Batch QR generation from CSV files

Mobile app for decryption

RSA-based secure key exchange

📚 References

NIST SP 800-38A – Block Cipher Modes

ISO/IEC 18004 – QR Code Standard

PyCryptodome Documentatio
