from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64 as e64

def RSA_asymetric_encrypt(msg, receiver_public_key):
    msg = str.encode(msg)
    rsa_public_key = RSA.importKey(receiver_public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encry_msg = rsa_public_key.encrypt(msg)
    encry_msg = e64.b64encode(encry_msg)
    return encry_msg

def RSA_asymetric_decrypt(encry_msg, receiver_private_key):
    rsa_private_key = RSA.importKey(receiver_private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    encry_msg = e64.b64decode(encry_msg)
    decry_msg = rsa_private_key.decrypt(encry_msg)
    return decry_msg


def Import_RSA_key(filepath):
    with open(filepath, mode='rb') as private_file:
        priv_key_data = private_file.read()
        private_key = RSA.importKey(priv_key_data)
        return private_key
