import re
from data_table_values import bin2hex, r, phi, SBoxDecimalTable, LTTable, LTTableInverse, IPTable, FPTable, SBoxBitstring, SBoxBitstringInverse, bitstring

# Utility functions
def hexstring2bitstring(hexstring):
    return bin(int(hexstring, 16))[2:].zfill(128)

def bitstring2hexstring(bitstring):
    return hex(int(bitstring, 2))[2:].zfill(32)

def xor(*args):
    if not args:
        raise ValueError("At least one argument needed")
    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result

def binaryXor(n1, n2):
    if len(n1) != len(n2):
        raise ValueError("Cannot XOR bitstrings of different lengths (%d and %d)" % (len(n1), len(n2)))
    result = "".join("0" if a == b else "1" for a, b in zip(n1, n2))
    return result

def rotateLeft(input, places):
    p = places % len(input)
    return input[-p:] + input[:-p]

def rotateRight(input, places):
    return rotateLeft(input, -places)

def shiftLeft(input, p):
    if abs(p) >= len(input):
        return "0" * len(input)
    if p < 0:
        return input[-p:] + "0" * len(input[:-p])
    return "0" * len(input[-p:]) + input[:-p]

def shiftRight(input, p):
    return shiftLeft(input, -p)

def reverseString(s):
    return s[::-1]

def applyPermutation(permutationTable, input):
    if len(input) != len(permutationTable):
        raise ValueError("Input size (%d) doesn't match perm table size (%d)" % (len(input), len(permutationTable)))
    return "".join(input[permutationTable[i]] for i in range(len(permutationTable)))

# Functions used in the formal description of the cipher
def S(box, input):
    try:
        return SBoxBitstring[box % 8][input]
    except KeyError:
        print(f"KeyError: box={box % 8}, input={input}")
        raise

def SInverse(box, output):
    try:
        return SBoxBitstringInverse[box % 8][output]
    except KeyError:
        print(f"KeyError: box={box % 8}, output={output}")
        raise

def SHat(box, input):
    return "".join(S(box, input[4 * i:4 * (i + 1)]) for i in range(32))

def SHatInverse(box, output):
    return "".join(SInverse(box, output[4 * i:4 * (i + 1)]) for i in range(32))

def LT(input):
    if len(input) != 128:
        raise ValueError("Input to LT is not 128 bits long")
    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result += outputBit
    return result

def LTInverse(output):
    if len(output) != 128:
        raise ValueError("Input to inverse LT is not 128 bits long")
    result = ""
    for i in range(len(LTTableInverse)):
        inputBit = "0"
        for j in LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result += inputBit
    return result

def IP(input):
    return applyPermutation(IPTable, input)

def FP(input):
    return applyPermutation(FPTable, input)

def IPInverse(output):
    return applyPermutation(FPTable, output)

def FPInverse(output):
    return applyPermutation(IPTable, output)

def R(i, BHati, KHat):
    xored = xor(BHati, KHat[i])
    SHati = SHat(i, xored)
    if 0 <= i <= r - 2:
        BHatiPlus1 = LT(SHati)
    elif i == r - 1:
        BHatiPlus1 = xor(SHati, KHat[r])
    else:
        raise ValueError("Round %d is out of 0..%d range" % (i, r - 1))
    return BHatiPlus1

def RInverse(i, BHatiPlus1, KHat):
    if 0 <= i <= r - 2:
        SHati = LTInverse(BHatiPlus1)
    elif i == r - 1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        raise ValueError("Round %d is out of 0..%d range" % (i, r - 1))
    xored = SHatInverse(i, SHati)
    BHati = xor(xored, KHat[i])
    return BHati

def encrypt(plainText, userKey):
    K, KHat = makeSubkeys(userKey)
    BHat = IP(plainText)
    for i in range(r):
        BHat = R(i, BHat, KHat)
    C = FP(BHat)
    return C

def decrypt(cipherText, userKey):
    K, KHat = makeSubkeys(userKey)
    BHat = FPInverse(cipherText)
    for i in range(r - 1, -1, -1):
        BHat = RInverse(i, BHat, KHat)
    plainText = IPInverse(BHat)
    return plainText

def makeSubkeys(userKey):
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i + 8) * 32:(i + 9) * 32]

    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1], bitstring(phi, 32), bitstring(i, 32)),
            11
        )

    k = {}
    for i in range(r + 1):
        whichS = (r + 3 - i) % r
        k[0 + 4 * i] = ""
        k[1 + 4 * i] = ""
        k[2 + 4 * i] = ""
        k[3 + 4 * i] = ""
        for j in range(32):
            input = w[0 + 4 * i][j] + w[1 + 4 * i][j] + w[2 + 4 * i][j] + w[3 + 4 * i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l + 4 * i] += output[l]

    K = ["".join(k[4 * i + j] for j in range(4)) for i in range(33)]
    KHat = [IP(K[i]) for i in range(33)]

    return K, KHat

# SerpentEncryptor and SerpentDecryptor classes
class SerpentEncryptor:
    def __init__(self, userKey):
        self.userKey = userKey
        self.K, self.KHat = makeSubkeys(userKey)

    def encrypt(self, plainText):
        bitstringPlaintext = hexstring2bitstring(plainText)
        encryptedBitstring = encrypt(bitstringPlaintext, self.userKey)
        return bitstring2hexstring(encryptedBitstring)

class SerpentDecryptor:
    def __init__(self, userKey):
        self.userKey = userKey
        self.K, self.KHat = makeSubkeys(userKey)

    def decrypt(self, cipherText):
        bitstringCiphertext = hexstring2bitstring(cipherText)
        decryptedBitstring = decrypt(bitstringCiphertext, self.userKey)
        return bitstring2hexstring(decryptedBitstring)