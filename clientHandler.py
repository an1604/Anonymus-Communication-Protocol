import socket
import threading
from message import Message


class ClientHandler(threading.Thread):
    def __init__(self, client_sock, server_public_key, server_secret_key, message_len):
        super().__init__()
        self.client_sock = client_sock
        self.server_public_key = server_public_key
        self.message_len = message_len  # The len of a single message.
        self.stop = False

        self.messages = None  # Object that stores all messages from the client.

    def run(self):
        try:
            self.client_sock.sendall(self.server_public_key)  # Send the server's public key first.
            while True:
                # Initiate the Message object.
                if self.messages is None:
                    self.messages = Message(self.message_len)

                # Extract the data by receiving the message from the client.
                data = self.client_sock.recv(1024).decode()
                self.messages.add_message(data)

                for msg in self.messages.get_messages():
                    self.client_sock.send(msg.encode())  # Send the messaged directly to the Bob/Alice.
                    # , (
                    # self.messages.ip, self.messages.port)
                self.messages = None

        except Exception as e:
            print(f"Exception occurred! {e}")

        finally:
            self.client_sock.close()
