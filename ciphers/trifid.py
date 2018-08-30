import string
from copy import copy
import numpy as np
import re

from cipher import Cipher


class Trifid(Cipher):
    """
    The trifid cipher is a classical cipher invented by Felix Delastelle and described in 1902. Extending the principles
    of Delastelle's earlier bifid cipher, it combines the techniques of fractionation and transposition to achieve a
    certain amount of confusion and diffusion: each letter of the ciphertext depends on three letters of the plaintext
    and up to three letters of the key.
    """

    def __init__(self, cube):
        super(Trifid, self).__init__()
        self.cube = cube

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
        plaintext = re.sub('[^%s]' % self.cube.alphabet, '', plaintext)
        ciphertext = list(plaintext)

        block_char_indices = np.zeros([3, key], dtype=np.uint8)
        block_chars = 0  # intra-block characters
        for i, pc in enumerate(plaintext):
            i_cube, j_cube, k_cube = self.cube.get_coordinates(pc)
            block_char_indices[0, block_chars] = i_cube
            block_char_indices[1, block_chars] = j_cube
            block_char_indices[2, block_chars] = k_cube
            block_chars += 1

            if block_chars == key or i == len(plaintext) - 1:
                # we're at the end of a block or message; dump the existing buffer to ciphertext
                i_fractioned = block_char_indices[:,:block_chars].flatten()
                i_fractioned = np.asarray([i_fractioned[::3], i_fractioned[1::3], i_fractioned[2::3]])
                for i_block_char in xrange(block_chars):
                    i_pc = i - block_chars + i_block_char + 1
                    ciphertext[i_pc] = self.cube.get_character(
                        i_fractioned[0, i_block_char],
                        i_fractioned[1, i_block_char],
                        i_fractioned[2, i_block_char]
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
        ciphertext = re.sub('[^%s]' % self.cube.alphabet, '', ciphertext)
        plaintext = list(ciphertext)

        block_char_indices = np.zeros(3*key, dtype=np.uint8)
        block_chars = 0  # intra-block characters
        for i, cc in enumerate(ciphertext):
            i_cube, j_cube, k_cube = self.cube.get_coordinates(cc)
            block_char_indices[3*block_chars] = i_cube
            block_char_indices[3*block_chars+1] = j_cube
            block_char_indices[3*block_chars+2] = k_cube
            block_chars += 1

            if block_chars == key or i == len(plaintext) - 1:
                i_unfractionated = block_char_indices[:3*block_chars].reshape([3, block_chars])
                # we're at the end of a block or message; dump the existing buffer to plaintext
                for i_block_char in xrange(block_chars):
                    i_cc = i - block_chars + i_block_char + 1
                    plaintext[i_cc] = self.cube.get_character(
                        i_unfractionated[0, i_block_char],
                        i_unfractionated[1, i_block_char],
                        i_unfractionated[2, i_block_char]
                    )
            block_chars %= key

        return ''.join(plaintext)


class Cube(object):
    """
    Cube for the Trifid cipher
    """

    def __init__(self, alphabet=None):
        """
        Parameters
        ----------
        alphabet (string): character string (layer-row-column ordered) with length a cube of the size
            e.g., 2**3 = 8, 3**3 = 27
            Note: by default, forms a cube with the standard lowercase english letters with a ? mark
        """

        if alphabet is None:
            self.alphabet = string.ascii_lowercase + '?'
        else:
            self.alphabet = alphabet.lower()

        self.height = self.width = int(len(self.alphabet) ** (1/3.))
        if self.height**3 != len(self.alphabet):
            raise ValueError("alphabet can not be placed into cube (wrong size)")

    def get_coordinates(self, c):
        """
        Parameters
        ----------
        c (char): character

        Returns:
            i (int): layer index of character in cube
            j (int): row index of character in cube
            k (int): col index of character in cube
        """

        c_id = self.alphabet.index(c)
        i = int(c_id / (self.width * self.height))
        j = int((c_id % (self.width * self.height)) / self.width)
        k = int((c_id % (self.width * self.height)) % self.width)

        return i, j, k

    def get_character(self, i, j, k):
        """
        Parameters
        ----------
        i (int): layer index into cube
        j (int): row index into cube
        k (int): col index into cube

        Returns
        -------
        c (char): character
        """

        return self.alphabet[i*self.width*self.height + j*self.width + k]
