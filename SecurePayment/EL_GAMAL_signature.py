import random
from hashlib import sha256
from ECDH_keys import modinv, ec_mult, ec_add

# Elliptic curve parameters (secp256k1)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Function to generate EC ElGamal signature
def sign_message(message, private_key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    z = int(sha256(message).hexdigest(), 16)
    r = s = 0
    while r == 0 or s == 0:
        k = random.randint(1, n-1)
        x, y = ec_mult(k, G, p)
        r = x % n
        s = ((z + r * private_key) * modinv(k, n)) % n
    return (r, s)

# Function to verify EC ElGamal signature
def verify_signature(message, signature, public_key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    r, s = signature
    z = int(sha256(message).hexdigest(), 16)
    w = modinv(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n
    x1, y1 = ec_mult(u1, G, p)
    x2, y2 = ec_mult(u2, public_key, p)
    x, y = ec_add((x1, y1), (x2, y2), p)
    return r == x % n
