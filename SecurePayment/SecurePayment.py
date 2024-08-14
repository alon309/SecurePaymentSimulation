import hashlib
import secrets
from serpent import hexstring2bitstring
from serpent_cipher_cbc import SerpentCipherCBC
from ECDH_keys import generate_ecdh_keypair, ecdh_key_agreement 
from EL_GAMAL_signature import sign_message, verify_signature

def derive_encryption_key(shared_key: bytes) -> str:
    # Hash the shared key using SHA-256
    hash_function = hashlib.sha256()
    hash_function.update(shared_key)
    hashed_key = hash_function.digest()
    
    # Convert the hash output to a binary string
    encryption_key_binary = ''.join(format(byte, '08b') for byte in hashed_key)
    
    return encryption_key_binary


def main():
    print('Alice paying Bob\n')

    # Alice and Bob perform key exchange using ECDH
    alice_private_key, alice_public_key = generate_ecdh_keypair()
    bob_private_key, bob_public_key = generate_ecdh_keypair()

    print(f'Alice private key: {alice_private_key}\nAlice public key: {alice_public_key}\n')
    print(f'Bob private key: {bob_private_key}\nBob public key: {bob_public_key}\n')

    # Use Alice's private key directly
    alice_private_key_hex = hex(alice_private_key)[2:].zfill(64)  # Convert to hex format and zero-pad to 64 hex characters
    alice_private_key_binary = bin(int(alice_private_key_hex, 16))[2:].zfill(256)  # Convert to binary format and zero-pad to 256 bits

    print(f'Alice private key (hex): {alice_private_key_hex}\n')
    print(f'Alice private key (binary): {alice_private_key_binary}\n')

    # Alice calculates shared key with Bob's public key
    alice_shared_key = ecdh_key_agreement(alice_private_key, bob_public_key)

    # Bob calculates shared key with Alice's public key
    bob_shared_key = ecdh_key_agreement(bob_private_key, alice_public_key)


    #calculate encryptio and decryption key usisng shared key
    encryption_decryption_key = derive_encryption_key(alice_shared_key)

    # Generate IV
    iv = secrets.token_bytes(16)  # 128-bit IV

    # Initialize SerpentCipherCBC with Alice's private key in binary format
    cipher = SerpentCipherCBC(encryption_decryption_key)

    # Demonstrate encryption and decryption
    plaintext = '4580458045804580 13/8/2040 5000$ Alice to Bob'
    ciphertext = cipher.encrypt_cbc(plaintext, iv)

    # Alice signs the encrypted payment data
    signature = sign_message(ciphertext, alice_private_key)

    # Bob verifies the signature (he have alice's public key)
    is_valid = verify_signature(ciphertext, signature, alice_public_key)
    print(f'Signature valid: {is_valid}')

    # Decrypt the message
    decrypted_text = cipher.decrypt_cbc(ciphertext, iv)

    print(f'Plaintext: {plaintext}')
    print(f'Ciphertext: {ciphertext}')
    print(f'Decrypted text: {decrypted_text}')


if __name__ == "__main__":
    main()
