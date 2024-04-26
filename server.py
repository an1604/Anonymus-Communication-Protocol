from Crypto.PublicKey import RSA
import socket
from datetime import datetime, timedelta
from Crypto.Cipher import PKCS1_OAEP
import traceback
import threading
import concurrent.futures

from templates_paths import PUBLIC_KEY_PATH, SECRET_KEY_PATH, HOST, PORT


def read_rsa_keys(PK_file_name, SK_file_name):  # The RSA key generation for the server
    with open(SK_file_name, 'r') as file:
        s_key = RSA.import_key(file.read()).export_key()
    with open(PK_file_name, 'rb') as file:
        p_key = RSA.import_key(file.read()).export_key()
    return p_key, s_key


def handle_client(client_socket: socket, client_address, PK, message_len, SK, deadline_time):
    try:
        msgs = []  # List of all messages
        start_time = datetime.now()

        SK = RSA.import_key(SK)  # Activating the secret key of the server.
        cipher = PKCS1_OAEP.new(SK)

        data = ''
        while not 'exit' in str(data).lower():
            data = client_socket.recv(1024)
            decrypted_data = cipher.decrypt(data)

            # Extract the parameters for sending back to the other user.
            params = bytearray(decrypted_data)[:14].decode()
            params = params.split(' ')
            print(f"params: {params}")
            ip = params[0]
            port = int(params[1])
            print(f"ip: {ip}, port: {port}")

            msgs.append(decrypted_data)

            # Timeout occurrence.
            current_time = datetime.now()
            if current_time - start_time >= timedelta(seconds=deadline_time):
                # Create a new socket for the next-edge-user, using the ip and port that extracted.
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((ip, port))
                    for m in msgs:  # Iterate over all the messages, and send them back to the client.
                        print(f"Sending {m} to {ip}:{port}")
                        sock.send(m)
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        client_socket.close()  # Close the client socket when done


class Server:
    def __init__(self):
        self.PK, self.SK = read_rsa_keys(PK_file_name=PUBLIC_KEY_PATH,
                                         SK_file_name=SECRET_KEY_PATH)  # The keys' generation phase.
        self.sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_STREAM)  # The main socket that will bind to the HOST & PORT
        self.message_len = 1000  # 1000 bytes for a single message.
        self.deadline_time = 10  # The deadline time for the server keeps client's messages before sent them.
        self.clients = []  # List of clients with their names, ports,and ip addresses.
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)  # Thread-pool executor

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
