import string
from copy import copy

import operator

from cipher import Cipher


class OneTimePad(Cipher):
    """
    Encipher and decipher using a one time pad
    """

    def __init__(self):
        super(OneTimePad, self).__init__()

        self._alphabet = str(string.ascii_lowercase)

    def encrypt(self, text, key, func=operator.add, include_foreign_chars=True):
        """
        Parameters:
            text (string): plaintext
            key (string): one time pad
            func (function): how to combine plaintext and key before modulo
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
            i_pc = self._alphabet.index(pc)
            i_kc = self._alphabet.index(key[i % len(key)])
            ciphertext[i] = self._alphabet[func(i_pc, i_kc) % len(self._alphabet)]

        return ''.join(ciphertext)

    def decrypt(self, text, key, func=operator.sub, include_foreign_chars=True):
        """
        Parameters:
            text (string): ciphertext
            key (string): one time pad
            func (function): how to combine ciphertext and key before modulo
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
            i_cc = self._alphabet.index(cc)
            i_kc = self._alphabet.index(key[i % len(key)])
            plaintext[i] = self._alphabet[func(i_cc, i_kc) % len(self._alphabet)]

        return ''.join(plaintext)
