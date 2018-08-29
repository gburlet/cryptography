from ciphers.bifid import Bifid, PolybiusSquare

ciphertext = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

remaining_chars = "ABCDEFGHIJLMNQUVWXZ"
for i_alpha_missing in xrange(len(remaining_chars)):
    # form alphabet with removed char
    alpha_missing = remaining_chars[i_alpha_missing]
    alphabet = "KRYPTOS" + remaining_chars[:i_alpha_missing] + remaining_chars[i_alpha_missing+1:]
    for map_char in alphabet:
        # form all mappings between chars
        char_map = (alpha_missing.lower(), map_char.lower())
        for period in xrange(1, 98):
            # test all periods up to cipher length
            tableau = PolybiusSquare(alphabet=alphabet, char_map=char_map)
            plaintext = Bifid(tableau).decrypt(ciphertext, period)
            if plaintext[63:69] == "BERLIN":
                print "CORRECT"
                print plaintext


#NYPVTTMZFPK
#BERLINCLOCK