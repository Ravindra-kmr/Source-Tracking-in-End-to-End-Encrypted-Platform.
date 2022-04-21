import socket
import argparse
import secrets
import pickle

from cryptography.hazmat.primitives import serialization

from utils import make_commit, check_commit, verify_sign, R_SIZE, COMMIT_SIZE
from platform import SRC_SIZE, SIG_SIZE 

BOT = secrets.token_bytes(SIG_SIZE + SRC_SIZE + COMMIT_SIZE + R_SIZE)


class User():
    def __init__(self):
        self.msg_fd_map = {}

        with open("platform_pub_key.pem", 'wb') as f:
            self.platform_pub_key = serialization.load_pem_public_key(f.read())
        
        return

    def author_msg(self, m):

        commit, r = make_commit(m)

        msg = (m, BOT, commit, r)
        
        return msg


    def forward_msg(self, msg):
        
        m, fd = msg

        commit, r = make_commit(BOT)

        return (m, fd, commit, r)


    def receive_msg(self, pd, msg):
        sigma, src = pd

        m, fd, commit, r = msg

        # verify sign
        if not verify_sign(self.platform_pub_key, sigma, commit + src):
            return None
        
        if fd == BOT:
            if not check_commit(commit, m, r):
                return None
            
            fd = (sigma, src, commit, r)

            return (m, fd)
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
            
            return (m, fd)


    def message_fds(self):
        return self.msg_fd_map

        

def main(name, platform_ip, platform_port):
    print(f"Hello {name}, Starting Client ...")
    HOST = ''                 
    print("Press ctrl+c to exit...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to Platform-Server at {platform_ip} on port \
                                     {platform_port} ...")
        s.connect((platform_ip, platform_port))
        print("Connection success!")




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