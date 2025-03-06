import random
import string

class SecurityUtils:
    @staticmethod
    def generate_password(length=15):
        return ''.join(
            random.choice(string.ascii_letters + string.digits + "@.,") for _ in range(length)
        )