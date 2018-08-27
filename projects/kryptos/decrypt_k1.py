# K1
from ciphers.vigenere import VigenereTableau, Vigenere

kryptos_alphabet = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
vtableau = VigenereTableau(alphabet=kryptos_alphabet, row_fill=0, col_fill=4)
cipher = Vigenere(tableau=vtableau)

ciphertext = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
keyword = "PALIMPSEST"
plaintext = cipher.decrypt(ciphertext, keyword)

print "K1"
print ciphertext
print plaintext