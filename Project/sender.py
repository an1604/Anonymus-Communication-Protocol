import time

from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from templates_paths import *


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
        dest_port = params[6]
        prefix = f'{dest_ip} {dest_port}'.encode()  # Prefix building for responding.
        symmetric_key = generate_symmetric_key(password=password, salt=salt_password)
    return {
        'password': password,
        'message': m,
        'servers_path': servers_path,
        'round': sending_round,
        'salt': salt_password,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'prefix': prefix,
        'symmetric_key': symmetric_key
    }


def create_new_message(params_for_msg):
    next_ip = params_for_msg['dest_ip']
    next_port = params_for_msg['dest_port']
    encoded_msg = params_for_msg['message'].encode()
    symmetric_key = params_for_msg['symmetric_key']
    servers_path = params_for_msg['servers_path']
    prefix = params_for_msg['prefix']

    encrypted_message = encrypt_message(encoded_msg, symmetric_key)
    encrypted_message = prefix + ' '.encode() + encrypted_message

    for i in range(len(servers_path) - 1, 0,
                   -1):  # Running a reverse for loop
        # to get all the encryption layers from the beginning to the end.


if __name__ == '__main__':
    params = extract_params_for_msg()
    current_round = 0
    # Waits till the current round will be the same as the requested round.
    while params['round'] != current_round:
        time.sleep(60)
        current_round += 1
    create_new_message(params)
