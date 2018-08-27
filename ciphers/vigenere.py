import string
from copy import copy
import numpy as np

from cipher import Cipher


class VigenereTableau(object):
    """
    Generate the tableau used within the Vigenere cipher
    """

    def __init__(self, alphabet=None, row_fill=0, col_fill=0):
        """
        Parameters
        ----------
        alphabet (string): alphabet characters
        row_fill (int): number of extra rows to append (cycling through alphabet)
        col_fill (int): number of extra cols to append (cycling through alphabet)

        Notes:
            - For classic Alberti Vigenere Tableau use:
                VigenereTableau(alphabet="abcdefghijklmnopqrstuvwxyz", row_fill=0, col_fill=0)
            - For Kryptos Tableau use:
                VigenereTableau(alphabet="KRYPTOSABCDEFGHIJLMNQUVWXZ", row_fill=0, col_fill=4)
        """

        if alphabet is None:
            alphabet = str(string.ascii_lowercase)
        self.alphabet = copy(alphabet).lower()
        self._row_fill = row_fill
        self._col_fill = col_fill

        num_alphabet_chars = len(alphabet)
        num_tableau_cols = num_alphabet_chars + col_fill
        num_tableau_rows = num_alphabet_chars + row_fill
        self.tableau = np.zeros([num_tableau_rows, num_tableau_cols], dtype=np.uint8)  # indices into alphabet array
        for i in xrange(num_tableau_rows):
            for j in xrange(num_tableau_cols):
                self.tableau[i, j] = (i + j) % num_alphabet_chars

    def encrypt_char(self, c, kc):
        """
        Encrypts a single character using the tableau

        Parameters
        ----------
        c (char): character to encrypt
        kc (char): character from key guiding lookup

        Returns
        -------
        (char): encrypted character
        """

        if c not in self.alphabet or kc not in self.alphabet:
            return

        j_tableau = self.alphabet.index(c)
        i_tableau = self.alphabet.index(kc)
        return self.alphabet[self.tableau[i_tableau, j_tableau]]

    def decrypt_char(self, c, kc):
        """
        Decrypts a single character using the tableau

        Parameters
        ----------
        c (char): character to decrypt
        kc (char): character from key guiding lookup

        Returns
        -------
        (char): decrypted character
        """

        if c not in self.alphabet or kc not in self.alphabet:
            return

        i_c = self.alphabet.index(c)
        i_tableau = self.alphabet.index(kc)
        j_tableau = np.argwhere(self.tableau[i_tableau,:] == i_c)[0][0]
        return self.alphabet[j_tableau]


    def __str__(self):
        tableau_str = ""
        num_alphabet_chars = len(self.alphabet)
        num_tableau_cols = num_alphabet_chars + self._col_fill
        num_tableau_rows = num_alphabet_chars + self._row_fill
        for i in xrange(num_tableau_rows):
            row = ""
            for j in xrange(num_tableau_cols):
                row += self.alphabet[self.tableau[i, j]]
            tableau_str += row
            if i != num_tableau_rows - 1:
                tableau_str += '\n'

        return tableau_str


class Vigenere(Cipher):
    """
    A Vigenere cipher: polyalphabetic substitution
    """

    def __init__(self, tableau):
        super(Vigenere, self).__init__()
        self.vtableau = tableau

    def encrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): plaintext
            key (string)
            include_foreign_chars (boolean): include chars outside the alphabet

        Returns:
            ciphertext (string)
        """

        plaintext = copy(text).lower()
        cipherkey = copy(key).lower()
        ciphertext = list(plaintext)
        i_key = 0
        for i, pc in enumerate(plaintext):
            if pc not in self.vtableau.alphabet:
                if include_foreign_chars:
                    ciphertext[i] = pc
                continue

            kc = cipherkey[i_key % len(cipherkey)]
            ciphertext[i] = self.vtableau.encrypt_char(pc, kc)
            i_key += 1

        return ''.join(ciphertext)

    def decrypt(self, text, key, include_foreign_chars=True):
        """
        Parameters:
            text (string): ciphertext
            key (string)
            include_foreign_chars (boolean): include chars outside the alphabet

        Returns:
            plaintext (string)
        """

        ciphertext = copy(text).lower()
        cipherkey = copy(key).lower()
        plaintext = list(ciphertext)
        i_key = 0
        for i, cc in enumerate(ciphertext):
            if cc not in self.vtableau.alphabet:
                if include_foreign_chars:
                    plaintext[i] = cc
                continue
            kc = cipherkey[i_key % len(cipherkey)]
            plaintext[i] = self.vtableau.decrypt_char(cc, kc)
            i_key += 1

        return ''.join(plaintext)
