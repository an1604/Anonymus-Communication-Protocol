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

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 2030
MESSAGE_PATH = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\messages1.txt"


def generate_symmetric_key(password, salt, key_size=16):
    key = scrypt(password, salt, key_size, N=2 ** 14, r=8, p=1)
    return key


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return ciphertext, cipher.iv


def decrypt_message(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message


class Client:
    def __init__(self, client_name, client_port, file_name=None):
        self.client_name = client_name
        self.client_ip = None
        self.client_port = client_port

        self.server_PK = None  # The server's public key, to encrypt the messages while sending to the server.
        self.server_PK_cipher = None
        self.symmetric_key = None  # The symmetric key for the communication between Alice and Bob.

        # Extracting the file's parameters for the communication.
        if file_name:
            with open(file_name, 'rb') as f:
                data = str(f.read())
                print(f"data from file: {data}")
                params = data.split(' ')
                self.m = params[0]
                self.servers_path = params[1].split(',')
                self.sending_round = params[2]
                self.password = params[3]
                self.salt_password = params[4]
                self.dest_ip = params[5]
                self.dest_port = params[6]
                self.symmetric_key = generate_symmetric_key(password=self.password, salt=self.salt_password)
                print(f"The symmetric key is {self.symmetric_key}")
        else:
            self.dest_ip = '_'.join(SERVER_HOST.split('.'))
            self.dest_port = str(SERVER_PORT)

        # Prefix building for responding.
        self.prefix = f'{self.dest_ip} {self.dest_port}'

        self.messages_sent = []
        self.messages_received = []

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # The connection socket
        self.run_client()

    def run_client(self):
        self.client.connect((SERVER_HOST, SERVER_PORT))
        PK = self.client.recv(1024).decode()  # Get the public key of the server.
        self.server_PK = RSA.import_key(PK)
        self.server_PK_cipher = PKCS1_OAEP.new(self.server_PK)
        user_input = ''

        while not 'exit' in user_input.lower():
            user_input = input('Message:')
            self.messages_sent.append(user_input)
            message_to_server = self.prefix + ' ' + user_input  # Concatenate the prefix to the actual message
            message_to_server_encoded = message_to_server.encode()

            # The encryption part uses the public key of the server
            encrypted_message = self.server_PK_cipher.encrypt(message_to_server_encoded)
            self.client.send(encrypted_message)

            self.receive_data()

        self.client.send(user_input.lower().encode())  # Sent the exit command to the server
        self.client.close()

    def receive_data(self, timeout=2.5):
        self.client.setblocking(False)
        start_time = time.time()
        while True:
            try:
                data_received = self.client.recv(1024).decode()
                if data_received:
                    print(f"Response: {data_received}")
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
