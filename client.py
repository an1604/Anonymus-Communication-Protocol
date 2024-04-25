import socket
from datetime import datetime, timedelta

from server import PORT, HOST


class Client:
    def __init__(self, client_name, client_port, server_ip, server_port):
        self.client_name = client_name
        self.client_ip = None
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_PK = None  # The server's public key, to encrypt the messages while sending to the server.
        self.first_reply = True  # Flag to check if the server's public key is coming.
        self.deadline_time = 10  # The deadline time to store all the messages that sent from the client in seconds.

        # Prefix building
        ip = '_'.join(self.server_ip.split('.'))
        port = str(self.server_port)
        self.prefix = f'{ip} {port}'

        self.messages_sent = []
        self.messages_received = []

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.run_client()

    def run_client(self):
        try:
            self.client.connect((self.server_ip, self.server_port))
            self.client_ip = self.client.getsockname()[0]
            PK = self.client.recv(1024).decode()  # Get the public key of the server.
            self.server_PK = PK

            receiver_name = input("Enter receiver name: ")

            start_time = datetime.now()
            while True:
                user_input = input(f'Message to {receiver_name}:')
                if user_input.lower() == 'exit':
                    break

                self.messages_sent.append({
                    'to': receiver_name,
                    'msg': user_input
                })

                # Checks the timer (10 sec timer)
                current_time = datetime.now()
                if current_time - start_time >= timedelta(seconds=self.deadline_time):
                    print('timeout!!!')
                    print("Sending the messages...")

                    # Sent all the messaged one by one to the server.
                    for message in self.messages_sent:
                        msg = self.prefix + ' ' + message['msg']  # Chain the prefix with the actual data.
                        message_encoded = msg.encode()
                        print(f"Message encoded from type: {type(message_encoded)}")

                        print(f'Sending message: {message}, the encode : {message_encoded}')
                        self.client.send(message_encoded)

                    data = self.client.recv(1024).decode()
                    if data:
                        self.messages_received.append({
                            'from': receiver_name,
                            'msg': data,
                        })
                        print(f'{receiver_name}: {data}')
                    start_time = datetime.now()  # Restart the timer.

            self.client.close()

        except Exception as e:
            print(f"Error: {e}")


if __name__ == '__main__':
    client = Client(client_name='alice', client_port=1234, server_port=PORT, server_ip=HOST)
