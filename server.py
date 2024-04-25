from Crypto.PublicKey import RSA
import socket
import random
from datetime import datetime
from clientHandler import ClientHandler


def generate_rsa_keys(key_size=2048):  # The RSA key generation for the server
    key = RSA.generate(key_size)
    p_key = key.publickey().export_key()
    s_key = key.export_key()
    return p_key, s_key


# TCP Host & Port
HOST = '127.0.0.1'
PORT = 2030


class Server:
    def __init__(self):
        self.stop = False
        self.PK, self.SK = generate_rsa_keys()  # The keys' generation phase.
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)  # The main socket that will bind to the HOST & PORT
        self.message_len = 1000  # 1000 bytes for a single message.
        self.clients = []  # List of clients with their names, ports,and ip addresses.
        print(f"The server is listening on {HOST}:{PORT}")
        self.sock.bind((HOST, PORT))  # The actual bind.
        self.sock.listen()

        self.run_server()

    def run_server(self):
        while True:
            client_sock, client_add = self.sock.accept()  # Accepting new connections (blocking call)
            print("Client hits the server!")

            # Setting a new thread for every client that hits the server.
            client_handler = ClientHandler(client_sock, self.PK, self.SK, self.message_len)
            client_handler.run()


if __name__ == '__main__':
    server = Server()
