from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
# Hash

default_algorithm = hashes.SHA256
# seleciona-se um dos vários algorimos implementados na package


def Hash(s):
    digest = hashes.Hash(default_algorithm(), backend=default_backend())
    digest.update(s)
    return digest.finalize()

# KDF


def kdf(salt):
    return PBKDF2HMAC(
        algorithm=default_algorithm(),   # SHA256
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()        # openssl
        )


def mac(key, source, tag=None):
    h = hmac.HMAC(key, default_algorithm(), default_backend())
    h.update(source)
    if tag is None:
        return h.finalize()
    h.verify(tag)
