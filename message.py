import random


class Message:
    def __init__(self, len_message):
        self.len_message = len_message
        self.messages = []
        self.id = random.randrange(1, 10000)  # Get a unique id to track the sequence

        # Data to extract from messages
        self.ip = None
        self.port = None

    def add_message(self, message):
        msg_list = message.split(" ")
        data = ' '.join(msg_list[2:])
        message_len = len(message)

        # Extract the ip and the port from the message
        self.set_ip_and_port(message)

        if message_len == self.len_message:
            self.messages.append(data)

        elif message_len < self.len_message:
            padded_message = data.ljust(self.len_message, '~')  # Padding the message to be in the same size
            self.messages.append(padded_message)

        else:
            self.separate_to_messages(data)  # Separate the big message into small blocks.

    def set_ip_and_port(self, msg_list):
        # Extract them only once, to keep the messages for a single target.
        if self.ip is None and self.port is None:
            ip = msg_list[0].replace('_', '.')  # Extract the ip address.
            port = int(msg_list[1])  # Extract the port from the message.

            if ip and port:
                self.ip = ip
                self.port = port

    def separate_to_messages(self, data):
        data_list = list(data)
        while len(data_list) > 0:
            msg = f'{self.ip}{self.port}'  # The prefix in every single message.
            for ch in data_list:
                if len(msg) == self.len_message:
                    self.messages.append(msg)
                    data_list.remove(ch)
                    break
                else:
                    msg += ch
                    data_list.remove(ch)

            if len(msg) < self.len_message:
                padded_message = msg.ljust(self.len_message, '~')  # Pad the message if it's not in the same len.
                self.messages.append(padded_message)

    def get_messages(self):
        return self.messages
