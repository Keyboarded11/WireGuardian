import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def encrypt(data, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode())
    return b'KWG1' + salt + nonce + AESGCM(key).encrypt(nonce, data, b'KWG1')


def decrypt(data, password):
    if data[:4] != b'KWG1':
        raise ValueError('Invalid backup format')
    key = Scrypt(salt=data[4:20], length=32, n=32768, r=8, p=1).derive(password.encode())
    return AESGCM(key).decrypt(data[20:32], data[32:], b'KWG1')
