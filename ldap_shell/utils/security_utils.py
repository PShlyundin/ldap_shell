import random
import string
import binascii
from Cryptodome.Hash import MD4


class SecurityUtils:
    @staticmethod
    def generate_password(length=15):
        """Generate a password that satisfies typical AD complexity rules."""
        if length < 8:
            length = 8
        categories = [
            string.ascii_uppercase,
            string.ascii_lowercase,
            string.digits,
            '!@#$%^&*',
        ]
        password = [random.choice(charset) for charset in categories]
        all_chars = ''.join(categories)
        password.extend(random.choice(all_chars) for _ in range(length - len(password)))
        random.shuffle(password)
        return ''.join(password)

    @staticmethod
    def calculate_ntlm(password):
        """Return the NT hash of a unicode password."""
        digest = MD4.new()
        digest.update(password.encode('utf-16le'))
        return binascii.hexlify(digest.digest()).decode()
