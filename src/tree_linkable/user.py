from curses.ascii import SI
import socket
import argparse
# import secrets
import os
import pickle

from cryptography.hazmat.primitives import serialization

from utils import make_commit, check_commit, verify_sign, R_SIZE, COMMIT_SIZE
from platform import SRC_SIZE, SIG_SIZE 

BOT = os.urandom(SIG_SIZE + SRC_SIZE + COMMIT_SIZE + R_SIZE)
# BOT = secrets.token_bytes(SIG_SIZE + SRC_SIZE + COMMIT_SIZE + R_SIZE)


class User():

    userid = 0

    def __init__(self, name, platform_ip, platfrom_port, plat_pub_key_file):
        self.name = name
        self.msg_fd_map = {}
        self.__class__.userid += 1
        self.id = self.__class__.userid

        with open(plat_pub_key_file, 'wb') as f:
            self.platform_pub_key = serialization.load_pem_public_key(f.read())
        
        self.platform_soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.platform_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.platform_soc.connect((platform_ip, platfrom_port))

        self.platform_soc.sendall(b'101' + name)
            
        return

    def author_msg(self, m, msgId):

        commit, r = make_commit(m)

        msg = (m, BOT, commit, r)

        self.platform_soc.sendall(b"102" + commit + msgId)
        
        return msg


    def forward_msg(self, msg, msgId):
        
        m, fd = msg

        commit, r = make_commit(BOT)

        self.platform_soc.sendall(b'102' + commit + msgId)

        return (m, fd, commit, r)


    def receive_msg(self, msg, e):

        # Request pd of msg having id e from platform.
        self.platform_soc.sendall(b'103' + e)

        data = self.platform_soc.recv(COMMIT_SIZE + SRC_SIZE + 3)
        code = data[:3]
        if code != b'104':
            # print(f"Received Code: {code}, Expected Code: 104")
            print "Received Code:{0}, Expected Code: 104".format(code)

        sigma, src = data[3: SIG_SIZE], data[SIG_SIZE:]

        m, fd, commit, r = msg

        # verify sign
        if not verify_sign(self.platform_pub_key, sigma, commit + src):
            return None
        
        if fd == BOT:
            if not check_commit(commit, m, r):
                return None
            
            fd = (sigma, src, commit, r)

            return fd
        else:
            sigma_fwd, src_fwd, commit_fwd, r_fwd = fd

            # verify commit of forwarder
            if not check_commit(commit, BOT, r):
                return None
            
            # verify commit of author
            if not check_commit(commit_fwd, m, r_fwd):
                return None
            
            # verify sign of platform on commit of author.
            if not verify_sign(
                        self.platform_pub_key, 
                        sigma_fwd, 
                        commit_fwd + src_fwd):
                return None
            
            return fd


    def message_fds(self):
        return self.msg_fd_map

    def report(self, m, fd):
        self.platform_soc.sendall(b'105' + fd + m)

        data = self.platform_soc.recv(2048)
        code = data[:3]
        if code != b'106':
            # print(f"Received Code: {code}, Expected Code: 104")
            print "Received Code:{0}, Expected Code: 106".format(code)
        
        return data[3:]


        

def main(name, platform_ip, platform_port):
    # print(f"Hello {name}, Starting Client ...")
    HOST = ''                 
    # print("Press ctrl+c to exit...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # print(f"Connecting to Platform-Server at {platform_ip} on port \
                                    #  {platform_port} ...")
        s.connect((platform_ip, platform_port))
        # print("Connection success!")




if __name__ == "__main__":


    parser = argparse.ArgumentParser()

    parser.add_argument( '-n', '--name',
                        help='Client will have this name',
                        required=True)

    parser.add_argument('-a', '--ip',
                        help='Client will connect to the platform at this ip-address',
                        required=True)

    parser.add_argument('-p', '--port',
                        help='Client will connect to the platform at this port address',
                        type=int,
                        required=True)

    args = parser.parse_args()

    main(args.name, args.ip, args.port)