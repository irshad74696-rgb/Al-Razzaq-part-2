🔐 Encrypting a file in Python takes one line. Making that encryption trustworthy took me the rest of the day.

This week I built a set of cryptography tools in Python: a SHA-256 hash calculator, a file integrity checker, a Fernet text encryptor, a password-based AES-256 file encryptor, an encrypted vault and a folder security audit.

The moment that taught me the most was a small experiment. I encrypted a file that said "Pay Ali 100 USD" with AES in CBC mode, the way many tutorials do it: salt + IV + ciphertext, nothing else. Then I tested it like an attacker would:

⚠️ About 1 wrong password in 256 "decrypted" without any error, and the script wrote garbage to disk as if all was fine.
⚠️ Flipping a single byte of the IV, without knowing the key, changed the message to "Pay Ali 900 USD".

Encryption kept the data secret, but nothing proved it was genuine. The fix was an HMAC-SHA256 over the whole file, checked before anything is decrypted. Now every wrong password and every changed byte is rejected, and no output is written.

What else I took away:
✅ SHA-256 proves a file did not change, but hides nothing. Encryption hides data, but on its own does not prove it is unchanged. You need both.
✅ A password is not a key. PBKDF2 with 600,000 rounds and a fresh salt per file makes every guess expensive.
✅ Key files and decrypted output must be created with mode 600. A secret.key readable by every user defeats the encryption.
✅ Never overwrite a key automatically. A new key means every old message is gone for good.
✅ Tests prove it: 19 automated tests cover tampered bytes, wrong passwords, padding edge cases and path tricks like ../../etc/passwd.

The scripts, tests and write-up are on my GitHub: https://github.com/irshad74696-rgb

Next up: AES-GCM, and public-key encryption with RSA.

#CyberSecurity #Cryptography #Python #InfoSec #AppSec #Encryption #BlueTeam #OpenToWork
