import threading
from datetime import datetime

from helper_functions import *
import socket


def receive_data(client, params_):
    data = client.recv(1024)
    symmetric_key = params_['symmetric_key']  # The receiver symmetric key
    data_decrypted = decrypt_message(key=symmetric_key, encrypted_data=data)
    message = data_decrypted.decode()
    time_ = datetime.now().time()
    time_ = time_.strftime("%H:%M:%S")
    print(f'{message} --> {time_}')


if __name__ == '__main__':
    # Extracting the ip and port for the receiver to listen on.
    msg_idx = sys.argv[1]
    if msg_idx.isdigit():
        params = extract_params_for_msg(msg_idx)
        receiver_ip = params['dest_ip']
        receiver_port = int(params['dest_port'])
        print(f"Receiver server listened on {receiver_ip}:{receiver_port}... ")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("", receiver_port))
        server.listen()

        while True:
            client_socket, client_address = server.accept()
            t = threading.Thread(target=receive_data(client_socket, params))
            t.start()
            client_socket.close()
    else:
        print(f"{msg_idx} is not a digit, try again.")
