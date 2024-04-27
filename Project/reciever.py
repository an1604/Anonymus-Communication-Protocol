import threading
from datetime import datetime

from helper_functions import *
from dynamic_templates_paths import *
import time
import socket


def receive_data(client, params_):
    data = client.recv(1024)
    symmetric_key = params_['symmetric_key']  # The receiver symmetric key
    data_decrypted = decrypt_message(key=symmetric_key, encrypted_data=data)
    message = data_decrypted.decode()
    time_ = datetime.now().time()
    time_ = time_.strftime("%H:%M:%S")
    print(message + time_)


if __name__ == '__main__':
    params = extract_params_for_msg()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("", RECEIVER_PORT))
    server.listen()

    while True:
        client_socket, client_address = server.accept()
        t = threading.Thread(target=receive_data(client_socket, params))
        t.start()
        client_socket.close()
