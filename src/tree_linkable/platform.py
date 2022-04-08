import socket
import argparse


class Platform():
    def init():
        # Generate keys
        pass

    def generate_pd(commit, userid):
        pass

    def report_msg(fd):
        pass

        
def main(port, file):

    print("Starting Platform ...")
    HOST = ''                 
    print("Press ctrl+c to exit...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        # socket_killer = GracefulSocketKiller(s)
        print(f"Start listening on port: {port}")
        # while not socket_killer.kill_now:
        while True:
            s.listen(2)
            conn, addr = s.accept()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port',
                        help='CA listens to this port',
                        type=int,
                        required=True)

    parser.add_argument('-o', '--outfilename',
                        help='CA writes diagnostics to this file',
                        required=True)

    args = parser.parse_args()

    main(args.port, args.outfilename)
