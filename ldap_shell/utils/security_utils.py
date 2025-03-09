import random
import string
import binascii
import hashlib
from impacket.structure import Structure
class SecurityUtils:
    @staticmethod
    def generate_password(length=15):
        return ''.join(
            random.choice(string.ascii_letters + string.digits + "@.,") for _ in range(length)
        )
    
    @staticmethod
    def calculate_ntlm (password):
        return binascii.hexlify(hashlib.new("md4", password.encode("utf-16le")).digest()).decode()
    
class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        ('QueryInterval','<L'),
        ('UnchangedInterval','<L'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)
        self['CurrentPassword'] = self.rawData[self['CurrentPassword']:self['CurrentPassword']+self['Length']]
        self['PreviousPassword'] = self.rawData[self['PreviousPassword']:self['PreviousPassword']+self['Length']]