import random
import sys
import time

from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
import socket
from datetime import datetime, timedelta
from Crypto.Cipher import PKCS1_OAEP
import traceback
import threading
import concurrent.futures

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad

from templates_paths import *

messages = []


def extract_addresses(single_server=None):
    ips = []
    with open(IPS, 'r') as f:
        for line in f:
            ips.append(line.strip())

    addresses = {}
    for idx, add in enumerate(ips):
        a = add.split(' ')
        ip = a[0]
        port = int(a[1])
        if single_server:
            if single_server == idx + 1:
                return ip, port
        else:
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


def extract_PKs(servers=None, single_server=None):
    if servers:
        pks = {}  # dictionary to store the public keys.
        for server_idx in servers:
            pk_path = PUBLIC_KEY_TEMPLATE.format(server_idx)
            with open(pk_path, 'rb') as f:  # Open the current file according to the server's index.
                pks[server_idx] = RSA.import_key(f.read()).export_key()
        return pks

    elif single_server:
        pk_path = PUBLIC_KEY_TEMPLATE.format(single_server)
        with open(pk_path, 'rb') as f:  # Open the current file according to the server's index.
            pk = RSA.import_key(f.read()).export_key()
            return pk


def send_message():
    temp_arr = messages.copy()
    random.shuffle(temp_arr)
    messages.clear()
    for msg in temp_arr:
        next_ip = msg[0]
        next_port = msg[1]
        data = msg[2]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((next_ip, next_port))
            s.send(data)
            s.close()
    time.sleep(60)


if __name__ == '__main__':
    Y_number = sys.argv[1]
    private_key = extract_PKs(single_server=Y_number)
    ip, port = extract_addresses(single_server=Y_number)
    t = threading.Thread(target=send_message)
    t.daemon = True
    t.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", int(port)))
    server.listen()

    while True:
        client_socket, client_address = server.accept()
        data = client_socket.recv(10000)

        if not data:
            break

        decrypted_msg = decrypt_message(key=private_key, encrypted_data=data)

        params = bytearray(decrypted_msg)[:14].decode()
        params = params.split(' ')
        next_ip = params[0]
        next_port = int(params[1])
        rest_of_data = decrypted_msg[14:]

        full_block = [rest_of_data, next_ip, next_port]
        messages.append(full_block)
        client_socket.close()

    server.close()
