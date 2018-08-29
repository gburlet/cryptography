import string
from copy import copy

from cipher import Cipher


class Xor(Cipher):
    """
    An XOR symmetric cipher (chars -> ASCII bytes -> XOR)
    """

    def __init__(self):
        super(Xor, self).__init__()

        self._alphabet = str(string.ascii_lowercase)

    def encrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): plaintext
            key (string): key that wraps around
            include_foreign_chars (boolean): include chars outside the alphabet

        Returns:
            ciphertext (string)
        """

        plaintext = copy(text).lower()
        ciphertext = list(plaintext)
        for i, pc in enumerate(plaintext):
            if pc not in self._alphabet:
                if include_foreign_chars:
                    ciphertext[i] = pc
                continue
            ciphertext[i] = chr(ord(pc) ^ ord(key[i % len(key)]))

        return ''.join(ciphertext)

    def decrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): ciphertext
            key (string): key that wraps around
            include_foreign_chars (boolean): include chars outside the alphabet

        Returns:
            plaintext (string)
        """

        return self.encrypt(text, key, include_foreign_chars)
