# SecurePaymentSimulation

This project implements a secure payment system using Elliptic Curve Cryptography (ECC) with a focus on the following cryptographic algorithms:
- **ECDH (Elliptic Curve Diffie-Hellman)** for secure key exchange.
- **Serpent in CBC (Cipher Block Chaining) Mode** for encryption and decryption.
- **EC ElGamal** for digital signatures to ensure message authenticity.

## Algorithms Overview

### 1. ECDH (Elliptic Curve Diffie-Hellman)
ECDH is used for securely exchanging cryptographic keys between two parties (e.g., Alice and Bob). It leverages elliptic curves to generate a shared secret, which can then be used to encrypt communications.

### 2. Serpent in CBC Mode
Serpent is a symmetric key block cipher that provides high security. When used in CBC mode, it chains the encryption of blocks together to enhance security by ensuring that identical plaintext blocks produce different ciphertext blocks.

### 3. EC ElGamal Signature
EC ElGamal is a method for creating digital signatures using elliptic curves. This ensures the authenticity and integrity of a message, allowing the receiver to verify that the message was indeed sent by the claimed sender and has not been tampered with.
