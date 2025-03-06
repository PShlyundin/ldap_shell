import random
import string
import binascii
import hashlib

class SecurityUtils:
    @staticmethod
    def generate_password(length=15):
        return ''.join(
            random.choice(string.ascii_letters + string.digits + "@.,") for _ in range(length)
        )
    
    @staticmethod
    def calculate_ntlm (password):
        return binascii.hexlify(hashlib.new("md4", password.encode("utf-16le")).digest()).decode()