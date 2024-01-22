from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json

def generate_aes_key():
    # Menghasilkan kunci AES 256-bit secara acak
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    password = b"your_secret_password"
    salt = b"your_salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt(data, key):
    # Mengenkripsi data menggunakan AES 256 CTR
    iv = b"your_random_iv"
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext)

def decrypt(ciphertext, key):
    # Mendekripsi data menggunakan AES 256 CTR
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

def add_watermark(ciphertext):
    # Menambahkan watermark pada hasil enkripsi
    watermark = b"your_watermark"
    return base64.b64encode(ciphertext + watermark)

def remove_watermark(encoded_data):
    # Menghilangkan watermark dari data terdekripsi
    decoded_data = base64.b64decode(encoded_data)
    watermark = decoded_data[-len(b"your_watermark"):]
    data_without_watermark = decoded_data[:-len(b"your_watermark")]
    return data_without_watermark

# Contoh data JSON yang akan dienkripsi
json_data = {"name": "John Doe", "age": 30, "city": "Example City"}

# Menghasilkan kunci AES
key = generate_aes_key()

# Mengenkripsi data JSON
encrypted_data = encrypt(json.dumps(json_data).encode(), key)

# Menambahkan watermark pada hasil enkripsi
data_with_watermark = add_watermark(encrypted_data)

# Simpan atau kirim data_with_watermark ke web service

# Hapus watermark dari data terdekripsi
decrypted_data = remove_watermark(data_with_watermark)

# Mendekripsi data JSON
decrypted_json_data = json.loads(decrypt(decrypted_data, key).decode())

# Output hasil dekripsi
print("Data terenkripsi dengan watermark:", data_with_watermark)
print("Data terdekripsi:", decrypted_json_data)