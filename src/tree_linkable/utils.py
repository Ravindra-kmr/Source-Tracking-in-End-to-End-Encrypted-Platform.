# import secrets
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from binascii import b2a_base64 as b2a

COMMIT_SIZE = 32
R_SIZE = 32
BOT = "lAe5SGopvwzGjOQ1UxgMzbBnSY6WGoVwvtk96LRELYilKTnG0FX1bxDZChnbOqt0XEEhrxArSoRcxbVw50wlAcDQ1A+CLGD5f7LC8bMWH3t4RSMQyT01V3Ag3Pp27+gZ/YJbX5U9Pqn3kXeVqL77c/trA0AdkIAJSL/IqcRSssGHJoEbDYO1kaCWctz9OAbGVzHbaHtAZFeNJctcQoId/lwuRZTslzX6HJzGoWSHJcrn9FoLCO9GoBcb7nBXksVB52Zv8ram75qQM/D7DmNyUjoqpTEhACxhM5KgtvBiNsf7IOXNnVWeK8CKnuRy1Hqgtb7ZTQ2I7zKk7faNVkeLldtxWvRGooqPR2e4MtU4TcWQ+0n865YiXo+xOJLVngcKBYf94tJ13qbU+GTr0skgm1hrU/ZwDeOk8f+Jn1Ynq3tstweAuLE+ORizDZSLa5FrXOTwEjMSXJunizgE2dsZJQ=="

log_file = open("out.txt", "w")

def check_commit(commit, m, r):
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(m + r)
    digest = hasher.finalize()

    return digest == commit

def make_commit(m):
    
    # r = secrets.token_bytes(R_SIZE)
    r = os.urandom(R_SIZE)
    hasher = hashes.Hash(hashes.SHA256())

    hasher.update(m + r)
    commit = hasher.finalize()

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