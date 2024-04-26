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

from templates_paths import BLOCK_SIZE, SERVER_HOST, SERVER_PORT, MESSAGE_PATH


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


class Client:
    def __init__(self, client_name, client_port, file_name):
        self.client_name = client_name
        self.client_ip = None
        self.client_port = client_port

        self.server_PK = None  # The server's public key, to encrypt the messages while sending to the server.
        self.server_PK_cipher = None
        self.symmetric_key = None  # The symmetric key for the communication between Alice and Bob.

        # Extracting the file's parameters for the communication.
        with open(file_name, 'rb') as f:
            data = str(f.read())
            params = data.split(' ')
            self.m = params[0]
            self.servers_path = params[1].split(',')
            self.sending_round = params[2]
            self.password = params[3]
            self.salt_password = params[4]
            self.dest_ip = params[5]
            self.dest_port = params[6]
            self.prefix = f'{self.dest_ip} {self.dest_port}'.encode()  # Prefix building for responding.
            self.symmetric_key = generate_symmetric_key(password=self.password, salt=self.salt_password)

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
            message_to_server = user_input.encode()  # Concatenate the prefix to the actual message

            # Encryption part
            encrypted_message = encrypt_message(message=message_to_server,
                                                key=self.symmetric_key)  # Ours symmetric key encryption.
            encrypted_message = self.prefix + ' '.encode() + encrypted_message  # Chain the IP and PORT to the beginning of the message without encryption.
            encrypted_message = self.server_PK_cipher.encrypt(encrypted_message)  # Server's PK encryption.

            print(f"Prefix: {self.prefix}")
            print(f"Message before sending: {encrypted_message}")

            self.messages_sent.append({
                'message': user_input,
                'encrypted_message': encrypted_message
            })

            self.client.send(encrypted_message)  # Sending the encrypted message to the server to decrypt it.
            self.receive_data()  # Waiting for data to receive back from the server.

        user_input = user_input.lower().encode()
        user_input = encrypt_message(message=user_input, key=self.symmetric_key)
        user_input = self.prefix + ' '.encode() + user_input
        user_input = self.server_PK_cipher.encrypt(user_input)
        self.client.send(user_input)  # Sent the exit command to the server
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
