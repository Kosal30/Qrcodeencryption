import sys
import os
import base64
import re
import qrcode
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, filedialog
from pathlib import Path
from PIL import Image
from pyzbar.pyzbar import decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Configuration & Key Setup ---
KEY_FILE = "key.txt"
DEFAULT_KEY = "A9f3K7pQ1sX8bT4zW6mR2vH0cY5nL3dE"
OUTPUT_DIR = "generated_qrs" # Folder where QR codes will be saved automatically

def load_clean_key():
    """Loads and sanitizes the 32-byte key."""
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "w") as f: 
            f.write(DEFAULT_KEY)
            
    with open(KEY_FILE, "rb") as f:
        raw = f.read()
    
    if raw.startswith(b'\xef\xbb\xbf'):
        raw = raw[3:]

    key_str = re.sub(r"\s+", "", raw.decode(errors='ignore'))
    key_str = key_str.replace("", "").strip() 
    key_str = key_str[:32].ljust(32, "0")
    return key_str.encode()

GLOBAL_KEY = load_clean_key()

# --- Logic Core ---
def generate_qr_logic(text, use_encryption=True):
    """Generates QR with optional AES encryption."""
    if use_encryption:
        iv = get_random_bytes(16)
        cipher = AES.new(GLOBAL_KEY, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
        final_data = base64.b64encode(iv + ct_bytes).decode() 
        mode_label = "ENCRYPTED"
    else:
        final_data = text
        mode_label = "PLAIN_TEXT"
    
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H, # type: ignore
        box_size=10,
        border=4,
    )
    qr.add_data(final_data)
    qr.make(fit=True)
    
    return qr.make_image(fill_color="black", back_color="white"), final_data, mode_label

def decrypt_logic(image_path):
    """Scans and decrypts QR content."""
    img = Image.open(image_path)
    decoded_list = decode(img)
    if not decoded_list: 
        raise ValueError("No QR code detected.")
    
    raw_data = decoded_list[0].data.decode()
    
    try:
        data = base64.b64decode(raw_data)
        iv, ct = data[:16], data[16:]
        cipher = AES.new(GLOBAL_KEY, AES.MODE_CBC, iv)
        result = unpad(cipher.decrypt(ct), AES.block_size).decode()
        return result, "Decrypted Secure QR"
    except Exception:
        return raw_data, "Standard QR (No Encryption)"

# --- GUI with Direct Saving ---
class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Auto-Save QR System")
        self.root.geometry("550x600")

        # Create output directory immediately
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

        self.encrypt_var = tk.BooleanVar(value=True)
        
        tk.Label(root, text="Step 1: Enter Text", font=("Arial", 12, "bold")).pack(pady=10)
        self.input_box = tk.Text(root, height=5)
        self.input_box.pack(padx=20, fill="x")

        tk.Checkbutton(root, text="Enable AES Encryption", variable=self.encrypt_var).pack(pady=5)

        tk.Button(root, text="Generate & Save Directly", command=self.handle_gen, 
                  bg="#4CAF50", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

        tk.Frame(root, height=2, bg="grey").pack(fill="x", pady=20)

        tk.Label(root, text="Step 2: Scan Existing QR", font=("Arial", 12, "bold")).pack(pady=5)
        tk.Button(root, text="Select QR Image", command=self.handle_read, 
                  bg="#2196F3", fg="white").pack(pady=5)

        self.output_box = tk.Text(root, height=8, bg="#f9f9f9")
        self.output_box.pack(padx=20, fill="x", pady=10)

    def handle_gen(self):
        text = self.input_box.get("1.0", tk.END).strip()
        if not text: 
            messagebox.showwarning("Warning", "Text box is empty!")
            return
        
        qr_img, payload, mode = generate_qr_logic(text, self.encrypt_var.get())
        
        # --- Direct Saving Logic ---
        # Creates a filename like: QR_ENCRYPTED_20231027_143005.png
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"QR_{mode}_{timestamp}.png"
        save_path = os.path.join(OUTPUT_DIR, filename)
        
        try:
            qr_img.save(save_path) #
            self.output_box.delete("1.0", tk.END)
            self.output_box.insert(tk.END, f"SAVED TO: {save_path}\n\nMODE: {mode}\nDATA: {payload}")
            messagebox.showinfo("Success", f"Saved directly to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    def handle_read(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if not file_path: return
        try:
            result, method = decrypt_logic(file_path)
            self.output_box.delete("1.0", tk.END)
            self.output_box.insert(tk.END, f"METHOD: {method}\n\nMESSAGE:\n{result}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()