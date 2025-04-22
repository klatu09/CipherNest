import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_message(message, key):
    try:
        f = Fernet(key)
        return f.encrypt(message.encode()).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def decrypt_message(message, key):
    try:
        f = Fernet(key)
        return f.decrypt(message.encode()).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def process_encrypt():
    password = password_entry.get()
    text = input_entry.get("1.0", tk.END).strip()

    if not password or not text:
        messagebox.showwarning("Missing Info", "Please enter both password and text.")
        return

    key = generate_key(password)
    result = encrypt_message(text, key)

    output_entry.delete("1.0", tk.END)
    output_entry.insert(tk.END, result)

def process_decrypt():
    password = password_entry.get()
    text = input_entry.get("1.0", tk.END).strip()

    if not password or not text:
        messagebox.showwarning("Missing Info", "Please enter both password and text.")
        return

    key = generate_key(password)
    result = decrypt_message(text, key)

    output_entry.delete("1.0", tk.END)
    output_entry.insert(tk.END, result)

def toggle_password():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        password_toggle_button.config(text="🙈 Hide Password")
    else:
        password_entry.config(show="*")
        password_toggle_button.config(text="👁️ Show Password")

# How to Use Window
def show_how_to_use():
    how_to_use_window = tk.Toplevel(root)
    how_to_use_window.title("How to Use")

    # Add content to the window
    instructions = (
        "1. Enter a password for encryption/decryption.\n"
        "2. Type the message you want to encrypt or decrypt in the message box.\n"
        "3. Click 'Encrypt Message' to encrypt the text, or 'Decrypt Message' to decrypt the text.\n"
        "4. The result will appear in the 'Output' box.\n\n"
        "Note: Ensure to use the same password for both encryption and decryption.\n"
        "For better security, use a strong password."
    )

    label = tk.Label(how_to_use_window, text=instructions, font=("Segoe UI", 10), justify="left", padx=10, pady=10)
    label.pack()

    close_button = tk.Button(how_to_use_window, text="Close", command=how_to_use_window.destroy, bg="#F44336", fg="white")
    close_button.pack(pady=6)

# --- GUI Setup ---
root = tk.Tk()
root.title("CipherNest - Encrypt / Decrypt")

tk.Label(root, text="Password:", font=("Segoe UI", 10)).pack()
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=4)

password_toggle_button = tk.Button(root, text="👁️ Show Password", command=toggle_password)
password_toggle_button.pack(pady=2)

tk.Label(root, text="Message / Encrypted Text:", font=("Segoe UI", 10)).pack()
input_entry = tk.Text(root, height=5, width=50)
input_entry.pack(pady=4)

# Encrypt Button
encrypt_button = tk.Button(root, text="Encrypt Message", command=process_encrypt, width=20, bg="#4CAF50", fg="white", font=("Segoe UI", 10, "bold"))
encrypt_button.pack(pady=6)

# Decrypt Button
decrypt_button = tk.Button(root, text="Decrypt Message", command=process_decrypt, width=20, bg="#F44336", fg="white", font=("Segoe UI", 10, "bold"))
decrypt_button.pack(pady=6)

tk.Label(root, text="Output:", font=("Segoe UI", 10)).pack()
output_entry = tk.Text(root, height=5, width=50)
output_entry.pack(pady=4)

# Help Button (How to Use)
help_button = tk.Button(root, text="How to Use", command=show_how_to_use, bg="#2196F3", fg="white", font=("Segoe UI", 10, "bold"))
help_button.pack(pady=6)

root.mainloop()
