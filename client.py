from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import socket
import traceback
import time
import errno
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad

from Project.templates_paths import *


def extract_addresses():
    ips = []
    with open(IPS, 'r') as f:
        for line in f:
            ips.append(line.strip())

    addresses = {}
    for idx, add in enumerate(ips):
        a = add.split(' ')
        ip = a[0]
        port = int(a[1])
        addresses[idx] = (ip, port)  # Key- server index, value - ip and port
    return addresses


def generate_symmetric_key(password, salt, key_size=16):
    key = scrypt(password, salt, key_size, N=2 ** 14, r=8, p=1)
    return key


def encrypt_message(message, key):
    iv = get_random_bytes(BLOCK_SIZE)  # Generate a random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, BLOCK_SIZE))
    return iv + ciphertext  # Prepend IV to the ciphertext


def decrypt_message(encrypted_data, key):
    iv = encrypted_data[:BLOCK_SIZE]  # Extract IV from the encrypted data
    ciphertext = encrypted_data[BLOCK_SIZE:]  # Extract ciphertext
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
    return decrypted_message


def extract_PKs(servers):
    pks = {}  # dictionary to store the public keys.
    for server_idx in servers:
        pk_path = PUBLIC_KEY_TEMPLATE.format(server_idx)
        with open(pk_path, 'rb') as f:  # Open the current file according to the server's index.
            pks[server_idx] = RSA.import_key(f.read()).export_key()
    return pks


class Client:
    def __init__(self, client_name, client_port, file_name):
        self.client_name = client_name
        self.client_ip = None
        self.client_port = client_port

        self.server_PK = None  # The server's public key, to encrypt the messages while sending to the server.
        self.server_PK_cipher = None
        self.symmetric_key = None  # The symmetric key for the communication between Alice and Bob.
        self.servers_addresses = extract_addresses()  # Dictionary of all the ip and port addresses for each server in the servers' path.

        # Extracting the file's parameters for the communication.
        with open(file_name, 'rb') as f:
            data = str(f.read())
            params = data.split(' ')
            self.m = params[0]
            self.servers_path = params[1].split(',')
            self.servers_PKs = extract_PKs(servers=self.servers_path)
            self.sending_round = params[2]
            self.password = params[3]
            self.salt_password = params[4]
            self.dest_ip = params[5]
            self.dest_port = params[6]
            self.prefix = f'{self.dest_ip} {self.dest_port}'.encode()  # Prefix building for responding.
            self.symmetric_key = generate_symmetric_key(password=self.password, salt=self.salt_password)

        self.messages_sent = []
        self.messages_received = []
        self.stop = False

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # The connection socket
        self.run_client()

    def run_client(self):
        self.client.connect((SERVER_HOST, SERVER_PORT))
        l 
        while not self.stop:
            self.messages_sent.append(self.m)
            message_to_server = self.m.encode()  # Concatenate the prefix to the actual message
            message_to_server = encrypt_message(message_to_server, self.symmetric_key)

            encrypted_message = encrypt_message(message=message_to_server,
                                                key=self.symmetric_key)  # Ours symmetric key encryption.
            encrypted_message = self.prefix + ' '.encode() + encrypted_message  # Chain the IP and PORT to the beginning of the message without encryption.
            for i in range(len(self.servers_path) - 1, 0,
                           -1):  # Running a reverse for loop
                # to get all the encryption layers from the beginning to the end.
                server_idx = self.servers_path[i]  # The actual index in the servers' path.
                server_ip, server_port = self.servers_addresses[server_idx]

                # The specific public key according to the server index.
                server_PK = self.servers_PKs[server_idx]
                server_PK = PKCS1_OAEP.new(server_PK)

                if server_PK and server_ip and server_port:
                    prefix = f"{server_ip} {server_port} {server_idx} {encrypted_message}".encode()  # The right prefix according to the specific server on the path.
                    encrypted_message = server_PK.encrypt(prefix)  # The encryption chaining.

            self.client.send(encrypted_message)  # Sending the encrypted message to the server to decrypt it.
            self.stop = True  # After sending the bomb, we can finish the client's task (for now).
            # self.receive_data()  # Waiting for data to receive back from the server.
        self.client.close()

    def receive_data(self, timeout=2.5):
        self.client.setblocking(False)
        start_time = time.time()
        while True:
            try:
                data_received = self.client.recv(1024)
                if data_received:
                    data_received_decrypted = decrypt_message(encrypted_data=data_received, key=self.symmetric_key)
                    print(f"Response: {data_received_decrypted}")
            except socket.error as e:
                # Handle non-blocking socket exception
                if e.errno == errno.EWOULDBLOCK:
                    pass  # No data available yet
                else:
                    print("Error:", e)
                    traceback.print_exc()

            # Check timeout
            if time.time() - start_time >= timeout:
                break
        self.client.setblocking(True)  # Restore blocking mode


if __name__ == '__main__':
    c = Client(client_name='alice', client_port=1234, file_name=MESSAGE_PATH)
