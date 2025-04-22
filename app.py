import base64
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=100000, backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_message(message: str, password: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding message to multiple of 16 bytes
    pad_length = 16 - (len(message.encode()) % 16)
    padded_message = message + chr(pad_length) * pad_length

    ct = encryptor.update(padded_message.encode()) + encryptor.finalize()
    encrypted = base64.b64encode(salt + iv + ct).decode()
    return encrypted


def decrypt_message(encrypted: str, password: str) -> str:
    try:
        data = base64.b64decode(encrypted.encode())
        salt, iv, ct = data[:16], data[16:32], data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ct) + decryptor.finalize()

        pad_length = padded_plain[-1]
        plain = padded_plain[:-pad_length].decode()
        return plain
    except Exception as e:
        return f"[!] Decryption failed: {str(e)}"


# GUI App
def create_gui():
    def encrypt_action():
        msg = msg_input.get("1.0", tk.END).strip()
        pwd = pwd_input.get().strip()
        if not msg or not pwd:
            messagebox.showerror("Error", "Message and password cannot be empty.")
            return
        result = encrypt_message(msg, pwd)
        output.delete("1.0", tk.END)
        output.insert(tk.END, result)

    def decrypt_action():
        encrypted = msg_input.get("1.0", tk.END).strip()
        pwd = pwd_input.get().strip()
        if not encrypted or not pwd:
            messagebox.showerror("Error", "Encrypted message and password required.")
            return
        result = decrypt_message(encrypted, pwd)
        output.delete("1.0", tk.END)
        output.insert(tk.END, result)

    root = tk.Tk()
    root.title("🛡️ CipherNest - AES Encryptor")

    tk.Label(root, text="🔑 Password:").pack(pady=2)
    pwd_input = tk.Entry(root, width=40, show="*")
    pwd_input.pack()

    tk.Label(root, text="💬 Message / Cipher Text:").pack(pady=2)
    msg_input = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=8)
    msg_input.pack()

    tk.Button(root, text="🔒 Encrypt", command=encrypt_action).pack(pady=5)
    tk.Button(root, text="🔓 Decrypt", command=decrypt_action).pack()

    tk.Label(root, text="📤 Output:").pack(pady=2)
    output = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=60, height=8)
    output.pack()

    root.mainloop()


if __name__ == "__main__":
    create_gui()
