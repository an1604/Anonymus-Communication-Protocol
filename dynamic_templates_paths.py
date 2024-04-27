from Crypto.Cipher import AES
import os

BLOCK_SIZE = AES.block_size  # Block size for the encryption process.
general_script_dir = os.path.dirname(
    os.path.abspath(__file__))  # The path to the directory of the current Python script

# All the other dynamic paths directories from the general directory path.
SECRET_KEY_PATH = os.path.join(general_script_dir, 'SKS')
PUBLIC_KEY_DIR = os.path.join(general_script_dir, 'PKS')

CONFIG_PATH = os.path.join(general_script_dir, 'Config')
MESSAGE_PATH = os.path.join(CONFIG_PATH, 'messages1.txt')
IPS = os.path.join(CONFIG_PATH, 'ips.txt')

# Templates for runtime extractions.
GENERAL_MESSAGE_PATH = os.path.join(CONFIG_PATH, 'messages{}.txt')
SECRET_KEY_TEMPLATE = os.path.join(SECRET_KEY_PATH, "sk{}.pem")
PUBLIC_KEY_TEMPLATE = os.path.join(PUBLIC_KEY_DIR, "pk{}.pem")
