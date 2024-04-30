import socket
import time

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
    # print(f"The encrypted message {encrypted_message}")
    last_server_index_in_order = servers_path[-1]
    # print(f'The last server to visit is {last_server_index_in_order}')
    first_pk_in_order = load_single_PK(last_server_index_in_order)
    cipher = PKCS1_OAEP.new(first_pk_in_order)
    l = cipher.encrypt(encrypted_message)

    if len(servers_path) > 1:
        n = len(servers_path) - 1
        sp_without_last = servers_path[:n]
        print(sp_without_last)
        for i in reversed(sp_without_last):
            print(f'The next server is {i}')
            f = load_single_PK(pk_index=i)  # Load the specific public key according to server's index.
            cipher = PKCS1_OAEP.new(f)
            ip, port = ips[i - 2], ports[i - 2]
            # print(f"Sending to {ip}:{port}")
            pfx = prefix_to_bytes(ip, port) + l  # Prefix building for responding.
            l = cipher.encrypt(pfx)
    # print(f"The encrypted message {l}")
    # !!! replaced next_ip, next_port with ip, port ( next_ip and next_port are the destination ip and port of the receiver not the server) - omer 28/4/24
    send_message(ips[-1], ports[-1], l, params_for_msg['servers_path'])
    # now we have a message encrypted with the public keys of all servers if needed


def send_message(ip, port, encrypted_message, servers_path):
    servers_path = '_'.join([str(num) for num in servers_path]).encode()
    if '_' in ip:
        ip = ip.replace('_', '.')
    with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s):
        print(f"Connecting to {ip}:{port}")
        s.connect((ip, int(port)))
        s.sendall(encrypted_message)
        s.close()
        print("Message successfully sent!")


if __name__ == '__main__':
    print("Sender is running...")
    params = extract_params_for_msg()
    print(f"params: {params}")
    current_round = 0
    # Waits till the current round will be the same as the requested round.
    # while params['round'] != current_round:
    #     time.sleep(5)
    #     current_round += 1
    create_new_message(params)
