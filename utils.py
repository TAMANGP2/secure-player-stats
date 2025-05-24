from Crypto.Cipher import AES
from base64 import b64encode, b64decode

key = b'Sixteen byte key'  # 16 bytes = 128 bits

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt_data(data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data)
    encrypted = cipher.encrypt(padded_data.encode('utf-8'))
    return b64encode(encrypted).decode('utf-8')

def decrypt_data(encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(b64decode(encrypted_data))
    return decrypted.decode('utf-8').strip()
