from ciphers.trifid import Trifid, Cube

ciphertext = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

cube = Cube(alphabet="KRYPTOSABCDEFGHIJLMNQUVWXZ?")
cipher = Trifid(cube)
for period in xrange(1, 98):
    # test all periods up to cipher length
    plaintext = cipher.decrypt(ciphertext, period)
    if plaintext[63:69] == "BERLIN":
        print "CORRECT"
        print plaintext

#NYPVTTMZFPK
#BERLINCLOCK