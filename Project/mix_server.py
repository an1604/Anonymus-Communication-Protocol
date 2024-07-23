import random
import threading
import time
from Crypto.Cipher import PKCS1_OAEP

from helper_functions import *
import socket
import argparse

messages = []  # The messages the server has to send at each round.
current_server_id = None  # variable to store the server id.
first = True
path_of_servers = None
current_port = None
ips, ports = load_IPORTS()  # Load the ips and ports of the servers.
my_id = None


def send_message():
    global current_port, messages, current_server_id, path_of_servers

    while True:
        tmp_arr = messages.copy()
        random.shuffle(tmp_arr)  # Sent the messages in random order.
        messages.clear()  # Clearing the list of messages to avoid duplications.
        for msg in tmp_arr:
            print("Message received!")
            # Extracting the relevant information.
            server_id = my_id
            ip = msg['ip']
            port = msg['port']
            data_ = msg['message']

            current_port = port  # Update the current port for the mix server new server.

            with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s):
                s.connect((ip, port))
                s.sendall(data_)

                print(f"New message sent to server {my_id}, on {ip}:{port}"
                      f"\nThe message is {data_}")

                s.close()
        print("Wait for a new message...")
        time.sleep(10)  # Sleeps for 10 sec to wait for new messages.


def extract_params_from_msg(msg, _id):
    server_sk = load_single_SK(_id)
    cipher = PKCS1_OAEP.new(server_sk)
    message_decrypted = cipher.decrypt(msg)
    ip = [str(b) for b in message_decrypted[:4]]
    ip = '.'.join(ip)
    port = int.from_bytes(message_decrypted[4:6], byteorder='big')
    data_ = message_decrypted[6:]
    return {
        'ip': ip,
        'port': port,
        'message': data_,
        'message_decrypted': message_decrypted,
    }


def main(_id):
    # Initialize a general server,
    # that will capture every data sent from any ip address to a random open port,
    # and execute the `send_message()` function.
    print("Set up mix server...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if _id.isdigit():
        server_id = int(_id)  # Get the id of the current server from the command line input

        server.bind(('', ports[server_id - 1]))
        server.listen()
        print(f"Server {server_id} listening...")

        t = threading.Thread(target=send_message)
        t.daemon = True
        t.start()

        while True:
            client_sock, client_address = server.accept()
            print(f"Client {client_address} connected")
            try:
                message = client_sock.recv(1024)
                msg_params = extract_params_from_msg(message,
                                                     server_id)  # The params extracted from the message (after decryption).
                messages.append(msg_params)
                client_sock.close()
            except Exception as e:
                print(f'Error: {e}')
    else:
        print(f"Server cannot be opened server {_id}, try again to insert server id.")
    server.close()


if __name__ == '__main__':
    # user_inpt
    parser = argparse.ArgumentParser(description='Message Sender Script')
    parser.add_argument('--server_id', type=str, help='The ID of the server')
    args = parser.parse_args()

    my_id = args.server_id
    time.sleep(3)
    main(my_id)
