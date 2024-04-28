from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad, pad

from Crypto.PublicKey import RSA
#import sys please dont delete 
# sys.path.append('/workspaces/Anonymus-Communication-Protocol') please dont delete 
# export PYTHONPATH=/workspaces/Anonymus-Communication-Protocol:$PYTHONPATH please dont delete 
from dynamic_templates_paths import *

RECEIVER_PORT = 2020  # The port that the receiver listens to.



def extract_params_for_msg():
    with open(MESSAGE_PATH, 'rb') as f:
        data = f.read().decode()
        print(data)
        params_ = data.split(' ')
        m = params_[0]
        servers_path = params_[1].split(',')
        sending_round = params_[2]
        password = params_[3]
        salt_password = params_[4]
        dest_ip = params_[5].replace('.', '_')
        dest_port = params_[6]
        prefix = f'{dest_ip}{dest_port}'.encode()  # Prefix building for responding.
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


def load_pks():
    pks = []
    for filename in os.listdir(PUBLIC_KEY_DIR):
        with open(os.path.join(PUBLIC_KEY_DIR, filename), 'rb') as f:
            p = RSA.import_key(f.read()).export_key()
            pks.append(p)
    return pks


def load_IPORTS():
    ips = []
    ports = []
    with open(IPS, 'rb') as f:
        for line in f:
            line = line.decode()
            ip, port = line.split(" ")
            ips.append(ip)
            ports.append(int(port))
            # print(f"IP: {ip}, Port: {port}")
    return ips, ports


def generate_symmetric_key(password, salt, key_size=16):  # Generate a symmetric key for sender and receiver.
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


def load_Sks():  # load all the secret keys from the directory.
    sks = []
    for filename in os.listdir(SECRET_KEY_PATH):
        with open(filename, 'rb') as f:
            sk = RSA.import_key(f.read()).export_key()
            sks.append(sk)
    return sks  # Output as a list of all the secret keys, by order.


def load_single_SK(sk_index):  # Given an index for a specific secret key, return only this one.
    sk_path = SECRET_KEY_TEMPLATE.format(sk_index)
    with open(sk_path, 'rb') as f:
        sk = RSA.import_key(f.read()).export_key()
        return RSA.import_key(sk)


def load_single_PK(pk_index):
    pk_path = PUBLIC_KEY_TEMPLATE.format(pk_index)
    with open(pk_path, 'rb') as f:
        pk = RSA.import_key(f.read()).export_key()
        return RSA.import_key(pk)


def prefix_to_bytes(ip, port):
    prefix = b''
    if '_' in ip:
        ip = ip.split('_')
    else:
        ip = ip.split('.')
    for num in ip:
        prefix += int(num).to_bytes(1, 'big')
    prefix += int(port).to_bytes(2, 'big')
    return prefix
