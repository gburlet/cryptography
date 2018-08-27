from copy import copy

from cipher import Cipher


class Scytale(Cipher):
    """
    A scytale cipher that historically involved rotating a leather wrap around a stick of a certain diameter,
    writing out the message, and then using a stick of the same diameter to decrypt
    """

    def __init__(self):
        super(Scytale, self).__init__()

    def encrypt(self, text, key, init_offset=0):
        """
        Parameters:
            text (string): plaintext
            key (int): number of characters to skip (mimics diameter of stick)
            init_offset (int): character offset to start at

        Returns:
            ciphertext (string)
        """

        plaintext = copy(text).lower()
        ciphertext = list(plaintext)
        num_chars = len(plaintext)
        for i in xrange(num_chars):
            ciphertext[(init_offset + i*key) % num_chars] = plaintext[i]

        return ''.join(ciphertext)

    def decrypt(self, text, key, init_offset=0):
        """
        Parameters:
            text (string): ciphertext
            key (int): rotation value for alphabet
            init_offset (int): character offset to start at

        Returns:
            plaintext (string)
        """

        ciphertext = copy(text).lower()
        plaintext = list(ciphertext)
        num_chars = len(ciphertext)
        for i in xrange(num_chars):
            plaintext[i] = ciphertext[(init_offset + i*key) % num_chars]

        return ''.join(plaintext)
