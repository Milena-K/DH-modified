from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import os
import hashlib


### dh ###
def generate_private_key():
    return ec.generate_private_key(ec.SECP256R1())

def generate_pub_key(private_key):
    return private_key.public_key()

def generate_shared_key(private_key, peer_pub_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_pub_key)
    # should I save the shared_key or the derived key?
    return derive_aes_key(shared_key)

def derive_aes_key(shared_key):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def encrypt_aes(name, shared_key, a_pub_key, b_pub_key, private_key):
    signed_hash = generate_signed_hash(name, a_pub_key, b_pub_key, private_key)
    nonce = os.urandom(16)
    encryptor = Cipher(
        algorithms.AES(shared_key),
        modes.CTR(nonce),
    ).encryptor()
    ciphertext = encryptor.update(signed_hash) + encryptor.finalize()
    return (ciphertext, nonce)

def decrypt_dh(shared_key, ciphertext_nonce):
    (ciphertext, nonce) = ciphertext_nonce
    decryptor = Cipher(
        algorithms.AES(shared_key),
        modes.CTR(nonce),
    ).decryptor()
    # this plaintext is in fact a signed hash
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

### dsa ###

def serialize_pub_keys(personal_pub_key, peer_pub_key):
    personal_pub_key_bytes = personal_pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    peer_pub_key_bytes = peer_pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pub_keys = [personal_pub_key_bytes, peer_pub_key_bytes]
    return pub_keys[0] + pub_keys[1]


def generate_signed_hash(name, a_pub_key, b_pub_key, private_key):
    pub_keys = serialize_pub_keys(a_pub_key, b_pub_key)
    signature = private_key.sign(
        pub_keys,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def verify_signed_hash(personal_pub_key, peer_pub_key, signature):
    pub_keys = serialize_pub_keys(peer_pub_key, personal_pub_key)
    try:
        peer_pub_key.verify(
            signature,
            pub_keys,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        print("Signature does not match")
        return False
