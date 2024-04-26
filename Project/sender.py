import socket
import time

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
from templates_paths import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding


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


def extract_params_for_msg():
    with open(MESSAGE_PATH, 'rb') as f:
        data = str(f.read())
        params = data.split(' ')
        m = params[0]
        servers_path = params[1].split(',')
        sending_round = params[2]
        password = params[3]
        salt_password = params[4]
        dest_ip = params[5]
        dest_port = params[6].split("'")[0]
        print(f'dest_port: {dest_port}')
        prefix = f'{dest_ip} {dest_port}'.encode()  # Prefix building for responding.
        symmetric_key = generate_symmetric_key(password=password, salt=salt_password)
    return {
        'password': password,
        'message': m,
        'servers_path': [int(i) for i in servers_path],
        'round': int(sending_round),
        'salt': salt_password,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'prefix': prefix,
        'symmetric_key': symmetric_key
    }



def load_pks(directory):
    pks = []
    for filename in os.listdir(directory):
        with open(os.path.join(directory, filename), 'rb') as f:
            p = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
            pks.append(p)
            
    return pks
def load_IPORTS(directory):
    ips = []
    ports = []
    with open(directory, 'r') as f:
        for line in f:
            ip, port = line.split(" ")
            ips.append(ip)
            ports.append(int(port))
    return ips, ports

def create_new_message(params_for_msg):
    next_ip = params_for_msg['dest_ip']
    next_port = params_for_msg['dest_port']
    encoded_msg = params_for_msg['message'].encode()
    symmetric_key = params_for_msg['symmetric_key']
    servers_path = params_for_msg['servers_path']
    prefix = params_for_msg['prefix']
    pks = load_pks(PUBLIC_KEY_DIR)
    ips, ports = load_IPORTS(IPS)

    encrypted_message = encrypt_message(encoded_msg, symmetric_key)
    print(f'prefix: {prefix}')
    encrypted_message = prefix + ' '.encode() + encrypted_message
    # [3,2,1] - > 
    print(f'Encrypted message: {encrypted_message}')
    f = pks[servers_path[-1]-1]
    l =  f.encrypt(encrypted_message,padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
    print(f'Encrypted message: {l}')
    if len(servers_path) > 1:
        for i in range(len(servers_path) - 2, 0,-1):
            f = pks[servers_path[i]-1]
            ip, port = ips[servers_path[i]-1], ports[servers_path[i]-1]
            pfx = f'{ip} {port}'.encode() + " ".encode() + l # Prefix building for responding.
            l = f.encrypt(pfx,padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
    send_message(next_ip, next_port, l)
    # now we have a message encrypted with the public keys of all servers if needed
    
def send_message(ip, port, encrypted_message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, int(port)))
        s.sendall(encrypted_message)
        s.close()



if __name__ == '__main__':
    params = extract_params_for_msg()
    current_round = 0
    # Waits till the current round will be the same as the requested round.
    while params['round'] != current_round:
        time.sleep(5)
        current_round += 1
    create_new_message(params)
