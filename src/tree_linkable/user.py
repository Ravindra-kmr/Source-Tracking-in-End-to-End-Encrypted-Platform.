import socket
import argparse


class User():
    def init():
        pass

    def author_msg():
        pass

    def forward_msg():
        pass

    def receive_msg():
        pass

        

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