from pylib import (
    creds,
    log
)
from base64 import b64encode, b64decode
# https://www.pycryptodome.org/src/hash/hash
from Crypto.Hash import SHA384
# https://www.pycryptodome.org/src/cipher/modern#gcm-mode
from Crypto.Cipher import AES

import simplejson as json


def digest(payload: str):
    log.debug(f'Digesting {len(payload)} bytes.')
    return SHA384.new(data=bytearray(payload, encoding='utf-8')).hexdigest()


def encrypt(header: str, payload: str):
    log.debug(f'Encrypting {len(payload)} bytes.')
    header = bytearray(header, encoding='utf-8')
    data = bytearray(payload, encoding='utf-8')
    key = b64decode(creds.aes_sym_key)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    json_v = [ b64encode(x).decode('utf-8') for x in (cipher.nonce, header, ciphertext, tag) ]
    return json.dumps(dict(zip(json_k, json_v)))


def decrypt(payload: str):
    if payload is None:
        return
    log.debug(f'Decrypting {len(payload)} bytes.')
    b64 = json.loads(payload)
    json_k = [ 'nonce', 'header', 'ciphertext', 'tag' ]
    jv = {k:b64decode(b64[k]) for k in json_k}
    key = b64decode(creds.aes_sym_key)
    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher.update(jv['header'])
    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return plaintext.decode('utf-8')