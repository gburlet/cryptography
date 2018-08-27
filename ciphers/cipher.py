from abc import abstractmethod, ABCMeta


class Cipher(object):
    """
    Abstract class for a cipher
    """

    __metaclass__ = ABCMeta

    def __init__(self):
        pass

    @abstractmethod
    def encrypt(self, text, key):
        pass

    @abstractmethod
    def decrypt(self, text, key):
        pass