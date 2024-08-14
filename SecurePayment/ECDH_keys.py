import random
from hashlib import sha256

# Elliptic curve parameters (secp256k1)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def modinv(a, p):
    # Extended Euclidean Algorithm for modular inverse
    lm, hm = 1, 0
    low, high = a % p, p
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % p

def ec_add(p1, p2, p):
    if p1 == (0, 0):
        return p2
    if p2 == (0, 0):
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        m = (3 * x1 * x1 + a) * modinv(2 * y1, p) % p
    else:
        m = (y2 - y1) * modinv(x2 - x1, p) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3

def ec_mult(k, point, p):
    result = (0, 0)
    addend = point
    while k:
        if k & 1:
            result = ec_add(result, addend, p)
        addend = ec_add(addend, addend, p)
        k >>= 1
    return result

# Function to generate ECDH key pair
def generate_ecdh_keypair():
    private_key = random.randint(1, p-1)
    public_key = ec_mult(private_key, G, p)
    return private_key, public_key

# Function to perform ECDH key agreement
def ecdh_key_agreement(private_key, public_key):
    shared_key = ec_mult(private_key, public_key, p)
    return sha256(str(shared_key).encode('utf-8')).digest()  # Derive a symmetric key
