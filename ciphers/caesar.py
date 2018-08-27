import string
from copy import copy

from cipher import Cipher


class Caesar(Cipher):
    """
    A caesar cipher that involves rotating the alphabet to [d]encrypt
    """

    def __init__(self):
        super(Caesar, self).__init__()

        self._alphabet = str(string.ascii_lowercase)

    def encrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): plaintext
            key (int): rotation value for alphabet
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
            ciphertext[i] = self._alphabet[(self._alphabet.index(pc) + key) % len(self._alphabet)]

        return ''.join(ciphertext)

    def decrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): ciphertext
            key (int): rotation value for alphabet
            include_foreign_chars (boolean): include chars outside the alphabet

        Returns:
            plaintext (string)
        """

        ciphertext = copy(text).lower()
        plaintext = list(ciphertext)
        for i, cc in enumerate(ciphertext):
            if cc not in self._alphabet:
                if include_foreign_chars:
                    plaintext[i] = cc
                continue
            plaintext[i] = self._alphabet[(self._alphabet.index(cc) - key) % len(self._alphabet)]

        return ''.join(plaintext)
