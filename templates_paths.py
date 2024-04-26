from Crypto.Cipher import AES

HOST = '127.0.0.1'
PORT = 2030

PUBLIC_KEY_PATH = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\pk2.pem"
SECRET_KEY_PATH = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\sk2.pem"
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 2030
MESSAGE_PATH = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\messages1.txt"
BLOCK_SIZE = AES.block_size

# Templates for runtime extractions.
PUBLIC_KEY_TEMPLATE = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\pk{}.pem"
SECRET_KEY_TEMPLATE = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\sk{}.pem"
MESSAGE_PATH_TEMPLATE = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\messages{}.txt"
IPS = r"C:\Users\adina\Desktop\תקיית_עבודות\אבטחת רשתות\ips.txt"
