import socket
import time
import sys
import argparse
from Crypto.Cipher import PKCS1_OAEP

from helper_functions import *


def create_new_message(params_for_msg):
    next_ip = params_for_msg['dest_ip']
    next_port = params_for_msg['dest_port']

    # Extracting the symmetric key and encrypt the message with it.
    symmetric_key = params_for_msg['symmetric_key']
    symmetric_encrypted_msg = encrypt_message(params_for_msg['message'].encode(), symmetric_key)
    servers_path = params_for_msg['servers_path']

    prefix = prefix_to_bytes(ip=next_ip, port=next_port)
    ips, ports = load_IPORTS()

    # Concatenating the prefix and the encrypted message together before encrypting again with the servers'
    # public keys.
    encrypted_message = prefix + symmetric_encrypted_msg
    last_server_index_in_order = servers_path[-1]
    first_pk_in_order = load_single_PK(last_server_index_in_order)
    cipher = PKCS1_OAEP.new(first_pk_in_order)
    l = cipher.encrypt(encrypted_message)

    if len(servers_path) > 1:
        n = len(servers_path) - 1
        sp_without_last = servers_path[:n]
        print(sp_without_last)
        for i in reversed(sp_without_last):
            f = load_single_PK(pk_index=i)  # Load the specific public key according to server's index.
            cipher = PKCS1_OAEP.new(f)
            ip, port = ips[i - 2], ports[i - 2]
            pfx = prefix_to_bytes(ip, port) + l  # Prefix building for responding.
            l = cipher.encrypt(pfx)
    send_message(ips[-1], ports[-1], l)
    # now we have a message encrypted with the public keys of all servers if needed


def send_message(ip, port, encrypted_message):
    if '_' in ip:
        ip = ip.replace('_', '.')
    with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s):
        print(f"Connecting to {ip}:{port}")
        s.connect((ip, int(port)))
        s.sendall(encrypted_message)
        s.close()
        print("Message successfully sent!")


def main(msg_idx):
    print("Sender is running...")
    if msg_idx.isdigit():
        params = extract_params_for_msg(msg_idx)
        print(f"params: {params}")
        current_round = 0
        # Waits till the current round will be the same as the requested round.
        while params['round'] != current_round:
            time.sleep(60)
            current_round += 1
        create_new_message(params)
    else:
        print(f"{msg_idx} is not a digit, try again.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Message Sender Script')
    parser.add_argument('--msg_idx', type=str, help='Message index to process')
    args = parser.parse_args()
    msg_idx = args.msg_idx

    main(msg_idx)
