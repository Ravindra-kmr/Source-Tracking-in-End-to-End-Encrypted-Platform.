import socket
import argparse
import pickle
import base64
import os
import threading
import sys
# import secrets
import os

from threading import RLock

lock = RLock()

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# sys.path.append("/home/jude/Mtech/Sem_2/NS/Project/src/tree_linkable")

from utils import check_commit, COMMIT_SIZE, R_SIZE, make_commit, verify_sign, log_file

# AES_KEY = secrets.token_bytes(32)
# CTR_NONCE = secrets.token_bytes(16)
AES_KEY = os.urandom(32)
CTR_NONCE = os.urandom(16)
RSA_KEY_SIZE = 2048

# SIG_SIZE = 32
# SRC_SIZE = RSA_KEY_SIZE / 8

# FD_SIZE = SIG_SIZE + SRC_SIZE + COMMIT_SIZE + R_SIZE

global_msgId_pd_map = {}

class PlatformTreeLinkable():
    
    def __init__(self, aes_key, ctr_nonce, rsa_key_size):
        
        # For encrypting source-id and metadata
        self.cipher = Cipher(algorithms.AES(aes_key), modes.CTR(ctr_nonce))

        # For signing encryption and commits
        self.private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=rsa_key_size,
                        )
        self.public_key = self.private_key.public_key()

        with open("platform_pub_key.pem", 'wb') as f:
            pem =  self.public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                    )

            f.write(pem)

        self.users = set()

        return


    def register_user(self, user_id):
        print "registered user", user_id
        self.users.add(user_id)


    def generate_pd(self, commit, userid, md=None):

        # Prepare tag
        encryptor = self.cipher.encryptor()
        userid_pkl = base64.b64encode(pickle.dumps(userid))
        md = base64.b64encode(pickle.dumps(md))
        s = userid_pkl + b"|" + md
        # print "Message being encrypted: {0}".format(s)
        src = encryptor.update(s) + encryptor.finalize()

        # Sign tag and commit
        sigma = self.private_key.sign(
                            commit + src,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH),
                            hashes.SHA256())

        print "generated pd for ", userid

        return (sigma, src)


    def report_msg(self, fd, m):
        sigma, src, commit, r = fd

        if not check_commit(commit, m, r):
            return None

        # try:
        #     self.public_key.verify(
        #                 sigma,
        #                 commit + src,
        #                 padding.PSS(
        #                     mgf=padding.MGF1(hashes.SHA256()),
        #                     salt_length=padding.PSS.MAX_LENGTH
        #                             ),
        #                 hashes.SHA256()
        #                         ) 
        # except InvalidSignature:
        #     return None
        if not verify_sign(self.public_key, sigma, commit + src):
            print "platform sign verification failed"
            return None
        
        decryptor = self.cipher.decryptor()

        pt = decryptor.update(src) + decryptor.finalize()

        pt = pt.decode("ascii").split("|")

        userid = pickle.loads(base64.b64decode(pt[0]))
        md = pickle.loads(base64.b64decode(pt[1]))

        print "reported user: ", userid

        return userid, md


def handle_user_scheme1(conn, addr, platform):
    

    data = conn.recv(2048)
    code, rest = data[:3], data[3:]
    
    if code == b'101':
        userid = rest
        platform.register_user(userid)

    else:
        # s = (f"Expected code 101, Received {code.encode('ascii')}: Failed to register user. Closing Connection")
        s = ("Expected code 101, Received {0}: Failed to register user. Closing Connection".format(code.encode('ascii')))
        msg = b'999' + s.encode('ascii')
        conn.sendall(msg)

        conn.close()
        
        return None

    while True:

        data = conn.recv(4096)

        if not data:
            print "{0} at {1} has disconnected.\n".format(userid, addr)
            # print(f"{userid} at {addr} has disconnected.")
            break

        code, rest = data[:3], data[3:]
        print "size of message ", len(rest)
        print "Received code ", code, "from user: ", userid 
        # print "msg :", rest
        # print "Id map", global_msgId_pd_map

        # Sending Commit
        if code == b'102':
            commit = rest[:COMMIT_SIZE]
            msg_id = rest[COMMIT_SIZE:]

            print "msg_id", msg_id

            pd = platform.generate_pd(commit, userid)
            with lock:
                global_msgId_pd_map[msg_id] = pd
        
        elif code == b'103':
            msg_id = rest
            
            with lock:
                sigma, src = global_msgId_pd_map[msg_id]
                del global_msgId_pd_map[msg_id]
            
            sigma = base64.b64encode(sigma)
            src = base64.b64encode(src)
            msg = b'104' + sigma + "|" + src 
            # print "Response: ", msg
            # Send to Receiver
            conn.sendall(msg)
        
        elif code == b'105':
            fd, m = rest.split("|")
            fd = pickle.loads(base64.b64decode(fd))

            # print "Reporting FD: ", fd, ", message: ", m
            source_id, md = platform.report_msg(fd, m)
            msg = b'106' + source_id
            
            # print "Response: ", msg
            
            conn.sendall(msg)

        elif code == b'999':
            # print(f"Received Code 999: {rest}")
            print "Received Code 999: {0}".format(rest)
        
        else:
            # s = f"Expected code 101, Received {code.encode('ascii')}"
            s = "Expected code 101, Received {}".format(code.encode('ascii'))
            msg = b'999' + s.encode('ascii')
            conn.sendall(msg)


def main(port):

    # print("Starting Platform ...")
    print "Starting Platform ..."

    platform = PlatformTreeLinkable(AES_KEY, CTR_NONCE, RSA_KEY_SIZE)
    
    HOST = ''                 
    
    print "Press ctrl+c to exit..."
    # print("Press ctrl+c to exit...")
    
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    # socket_killer = GracefulSocketKiller(s)
    print "Start listening on port: {0}".format(port)
    # print(f"Start listening on port: {port}")
    # while not socket_killer.kill_now:
    while True:
        s.listen(2)
        conn, addr = s.accept()

        print "Connected to {0}".format(addr)
        # print(f"Connected to {addr}")

        t = threading.Thread(target=handle_user_scheme1, args=(conn, addr, platform))
        t.start()



if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port',
                        help='Platform listens to this port',
                        type=int,
                        required=True)

    # parser.add_argument('-o', '--outfilename',
    #                     help='Platform writes diagnostics to this file',
    #                     required=True)

    args = parser.parse_args()

    # main(args.port, args.outfilename)
    main(args.port)

    log_file.close()
