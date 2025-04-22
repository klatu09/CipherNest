# 🛡️ CipherNest

A sleek, minimalistic **AES Encryption/Decryption** tool built with Python and a GUI powered by Tkinter. CipherNest encrypts your messages using **AES-256 in CBC mode**, wrapped with password-based protection via **PBKDF2**. Built for simplicity, security, and stealthy vibes.

---

## 💡 Features
- 🔐 AES-256 Encryption (CBC Mode)
- 🧂 Random Salt & IV generation
- 🧪 Password-based key derivation (PBKDF2-HMAC-SHA256)
- 🔁 Reversible encryption/decryption
- 🖥️ Simple Tkinter-based GUI
- 🧼 Clean, minimalist interface

---

## 📸 Preview

> *(Insert screenshot here)*

---

## ⚙️ How It Works
1. Type your message.
2. Choose a password (this acts as your encryption key).
3. Hit **Encrypt** to cipher the message.
4. Paste the encrypted text + password to **Decrypt** it later.

All data is encoded with **Base64**, and the salt/IV are embedded directly in the output for seamless decoding.

---

## 🧱 Built With
- [`cryptography`](https://pypi.org/project/cryptography/)
- `tkinter` (Python standard library)

---

## 🧠 Notes
- Your password is never stored.
- Salt and IV are auto-generated and packed inside the output.
- Do not lose your password — there's no backdoor.

---

## 🧑‍💻 Author
**Klatu**
Cybersecurity Enthusiast 
📫 LinkedIn · 💼 Portfolio


## 📜 License
MIT License – do whatever you want, just don't make it evil.



