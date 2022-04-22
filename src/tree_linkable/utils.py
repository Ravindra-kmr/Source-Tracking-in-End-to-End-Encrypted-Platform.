# import secrets
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

COMMIT_SIZE = 32
R_SIZE = 32


def check_commit(commit, m, r):
    hasher = hashes.Hash(hashes.SHA256())
    digest = hasher.update(m + r).finalize()

    return digest == commit

def make_commit(m):
    
    # r = secrets.token_bytes(R_SIZE)
    r = os.urandom(R_SIZE)
    hasher = hashes.Hash(hashes.SHA256())

    commit = hasher.update(m + r).finalize()

    return (commit, r)


def verify_sign(pub_key, sign, data):
    try:
        pub_key.verify(
                    sign,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                                ),
                    hashes.SHA256()
                            ) 
    except InvalidSignature:
        return False
    
    return True