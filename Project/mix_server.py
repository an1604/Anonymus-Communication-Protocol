import random
import threading
import time
import traceback
import sys
from Crypto.Cipher import PKCS1_OAEP

from helper_functions import *
import socket
messages = []  # The messages the server has to send at each round.
current_server_id = None  # variable to store the server id.
first = True
path_of_servers = None
current_port = None
ips, ports = load_IPORTS() # Load the ips and ports of the servers.
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
            if my_id:
                server_id = my_id
                ip = msg['ip']
                port = msg['port']
                data_ = msg['message']

                current_port = port  # Update the current port for the mix server new server.
                # t1 = threading.Thread(target=make_server)

                with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s):
                    # print(f"Connecting to {ip}:{port}")
                    s.connect((ip, port))
                    s.sendall(data_)

                    print(f"New message sent to server {my_id}, on {ip}:{port}"
                          f"\nThe message is {data_}")

                    s.close()
        print("Wait for a new message...")
        time.sleep(10)  # Sleeps for 10 sec to wait for new messages.


def make_server():
    stop = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', current_port))
    sock.listen()
    while not stop:
        conn, addr = sock.accept()
        with conn:
            print("New connection established!")
            data = conn.recv(1024)


def extract_params_from_msg(msg):
    # Global variables that will be used in this function.
    global current_server_id
    global first
    global path_of_servers
    # print(f"Current server id: {current_server_id}")
    # print("Congrats you got a msg!")
    server_sk = load_single_SK(my_id)
    cipher = PKCS1_OAEP.new(server_sk)
    # print(f"Messageeeeeeee: {message}")
    message_decrypted = cipher.decrypt(message)
    # print(f"Decrypted received message: {message_decrypted}")
    ip = [str(b) for b in message_decrypted[:4]]
    ip = '.'.join(ip)
    port = int.from_bytes(message_decrypted[4:6], byteorder='big')
    # print(f"IP: {ip}, Port: {port}")
    data_ = message_decrypted[6:]
    return {
        'ip': ip,
        'port': port,
        'message': data_,
        'message_decrypted': message_decrypted,
    }



if __name__ == '__main__':
    first = True
    # Initialize a general server,
    # that will capture every data sent from any ip address to a random open port,
    # and execute the `send_message()` function.
    print("Set up mix server...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TODO: Change the port to be as a function of the server id given at birth of the server object. ATM its server 3's port for debugging purposes.
    # TODO: when the server is born it should know its id and its port. it does this by reading the file that contains the server id and the port.
    # TODO: the server id is the index of the server in the list of servers and the port is the port that the server will listen to. given to us in the ips.txt file.
    # example: for server in server_list:
    #           server_id = server_list.index(server)
    #           mix_server(server_id)
    my_id = int(sys.argv[1])
    server.bind(('', ports[my_id - 1]))
    server.listen()
    print(f"Server {my_id} listening...")

    t = threading.Thread(target=send_message)
    t.daemon = True
    t.start()
    

    while True:
        client_sock, client_address = server.accept()
        print(f"Client {client_address} connected")
        try:
            # if first:
            #     first = False
            #     path_of_servers = client_sock.recv(5)
            #     path_of_servers = [int(num) for num in path_of_servers.split('_')]
            #     current_server_id = path_of_servers[0]
            #     path_of_servers = path_of_servers[1:]

            message = client_sock.recv(1024)
            msg_params = extract_params_from_msg(message)  # The params extracted from the message (after decryption).
            messages.append(msg_params)
            client_sock.close()
        except Exception as e:
            print(f'Error: {e}')
            traceback.print_exc()
    server.close()
