from Crypto.PublicKey import RSA
import socket
from datetime import datetime, timedelta
from Crypto.Cipher import PKCS1_OAEP
import traceback

import concurrent.futures

HOST = '127.0.0.1'
PORT = 2030


def generate_rsa_keys(key_size=2048, PK_file_name=None, SK_file_name=None):  # The RSA key generation for the server
    if SK_file_name is None and PK_file_name is None:
        # If the filename is None, we generate a 2048-bit random key.
        key = RSA.generate(key_size)
        p_key = key.publickey().export_key()
        s_key = key.export_key()
    else:  # Otherwise, we're reading the key from the file
        with open(SK_file_name, 'r') as file:
            s_key = RSA.import_key(file.read()).export_key()
        with open(PK_file_name, 'rb') as file:
            p_key = RSA.import_key(file.read()).export_key()

    return p_key, s_key


def handle_client(client_socket: socket, client_address, PK, message_len, SK, deadline_time):
    try:
        client_socket.send(PK)  # Send the server's public key to the client
        msgs = []  # List of all messages
        start_time = datetime.now()

        SK = RSA.import_key(SK)  # Activating the secret key of the server.
        cipher = PKCS1_OAEP.new(SK)

        data = ''
        while not 'exit' in str(data).lower():
            data = client_socket.recv(1024)
            decrypted_data = cipher.decrypt(data).decode()
            data = decrypted_data.encode()
            msgs.append(data)

            # Timeout occurrence.
            current_time = datetime.now()
            if current_time - start_time >= timedelta(seconds=deadline_time):
                for m in msgs:  # Iterate over all the messages, and sent them back to the client.
                    client_socket.send(m)

                msgs.clear()  # Clear the messages' list till the next timeout
                start_time = datetime.now()  # Restart the timer.
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        client_socket.close()  # Close the client socket when done


class Server:
    def __init__(self):
        self.PK, self.SK = generate_rsa_keys()  # The keys' generation phase.
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)  # The main socket that will bind to the HOST & PORT
        self.message_len = 1000  # 1000 bytes for a single message.
        self.deadline_time = 10  # The deadline time for the server keeps client's messages before sent them.
        self.clients = []  # List of clients with their names, ports,and ip addresses.
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=5)  # Thread-pool executor

        print(f"The server is listening on {HOST}:{PORT}")
        self.sock.bind((HOST, PORT))  # The actual bind.
        self.sock.listen()

        self.run_server()

    def run_server(self):
        while True:
            client_socket, client_address = self.sock.accept()
            print(f"New client connected: {client_address}")
            self.pool.submit(handle_client, client_socket, client_address, self.PK, self.message_len, self.SK,
                             self.deadline_time)


if __name__ == '__main__':
    server = Server()
