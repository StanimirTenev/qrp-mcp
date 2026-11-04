import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def issue(claims, key):
    return jwt.encode(claims, key, algorithm="RS256")

def session_key():
    return AESGCM.generate_key(bit_length=128)

def ephemeral():
    return ec.generate_private_key(ec.SECP384R1())

import oqs
def partner_kem():
    return oqs.KeyEncapsulation("ML-KEM-768")
