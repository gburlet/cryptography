import string
from copy import copy
import numpy as np
import re

from cipher import Cipher


class Bifid(Cipher):
    """
    Bifid is a cipher which combines the Polybius square with transposition, and uses fractionation to achieve diffusion
    It was invented by Felix Delastelle. Delastelle was a Frenchman who invented several ciphers including the bifid,
    trifid, and four-square ciphers.
    """

    def __init__(self, tableau):
        super(Bifid, self).__init__()
        self.tableau = tableau

    def encrypt(self, text, key):
        """
        Parameters:
            text (string): plaintext
            key (int): period for encryption

        Note: foreign characters are removed

        Returns:
            ciphertext (string)
        """

        plaintext = copy(text).lower()
        plaintext = re.sub('[^%s]' % self.tableau.alphabet, '', plaintext)
        ciphertext = list(plaintext)

        block_char_indices = np.zeros([2, key], dtype=np.uint8)
        block_chars = 0  # intra-block characters
        for i, pc in enumerate(plaintext):
            i_polybius, j_polybius = self.tableau.get_coordinates(pc)
            block_char_indices[0, block_chars] = i_polybius
            block_char_indices[1, block_chars] = j_polybius
            block_chars += 1

            if block_chars == key or i == len(plaintext) - 1:
                # we're at the end of a block or message; dump the existing buffer to ciphertext
                i_fractioned = block_char_indices[:,:block_chars].flatten()
                i_fractioned = np.asarray([i_fractioned[::2], i_fractioned[1::2]])
                for i_block_char in xrange(block_chars):
                    i_pc = i - block_chars + i_block_char + 1
                    ciphertext[i_pc] = self.tableau.get_character(
                        i_fractioned[0, i_block_char],
                        i_fractioned[1, i_block_char]
                    )
            block_chars %= key

        return ''.join(ciphertext)

    def decrypt(self, text, key):
        """
        Parameters:
            text (string): ciphertext
            key (int): rotation value for alphabet

        Note: foreign characters are removed

        Returns:
            plaintext (string)
        """

        ciphertext = copy(text).lower()
        ciphertext = re.sub('[^%s]' % self.tableau.alphabet, '', ciphertext)
        plaintext = list(ciphertext)

        block_char_indices = np.zeros(2*key, dtype=np.uint8)
        block_chars = 0  # intra-block characters
        for i, cc in enumerate(ciphertext):
            i_polybius, j_polybius = self.tableau.get_coordinates(cc)
            block_char_indices[2*block_chars] = i_polybius
            block_char_indices[2*block_chars+1] = j_polybius
            block_chars += 1

            if block_chars == key or i == len(plaintext) - 1:
                i_unfractionated = block_char_indices[:2*block_chars].reshape([2, block_chars])
                # we're at the end of a block or message; dump the existing buffer to plaintext
                for i_block_char in xrange(block_chars):
                    i_cc = i - block_chars + i_block_char + 1
                    plaintext[i_cc] = self.tableau.get_character(
                        i_unfractionated[0, i_block_char],
                        i_unfractionated[1, i_block_char]
                    )
            block_chars %= key

        return ''.join(plaintext)


class PolybiusSquare(object):
    """
    Tableau for the Bifid cipher
    """

    def __init__(self, alphabet=None, char_map=('j','i')):
        """
        Parameters
        ----------
        alphabet (string): 25 character string (row ordered) to form 5 x 5 grid
        char_map (character pair): map char [0] -> [1]
        """

        if alphabet is None:
            self.alphabet = string.ascii_lowercase
            self.tableau_alphabet = ''.join(sorted(list(set(self.alphabet) - set(char_map[0]))))
        else:
            self.alphabet = sorted(alphabet.lower() + char_map[0].lower())
            self.tableau_alphabet = alphabet.lower()

        self.height = self.width = 5
        self.char_map = (char_map[0].lower(), char_map[1].lower())

    def get_coordinates(self, c):
        """
        Parameters
        ----------
        c (char): character

        Returns:
            i (int): row index of character in polybius square
            j (int): col index of character in polybius square
        """

        c = self.char_map[1] if c == self.char_map[0] else c
        c_id = self.tableau_alphabet.index(c)
        i = int(c_id / self.width)
        j = c_id % self.width

        return i, j

    def get_character(self, i, j):
        """
        Parameters
        ----------
        i (int): row index into polybius square
        j (int): col index into polybius square

        Returns
        -------
        c (char): character
        """

        return self.tableau_alphabet[i*self.width + j]
