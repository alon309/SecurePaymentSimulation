import secrets
from serpent import hexstring2bitstring, SerpentEncryptor, bitstring2hexstring, SerpentDecryptor

def pkcs7_padding(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpadding(data):
    padding_len = data[-1]
    return data[:-padding_len]

def generate_random_hex_key(length):
    random_bytes = secrets.token_bytes(length // 2)
    random_hex_key = random_bytes.hex()
    return random_hex_key

class SerpentCipherCBC:
    def __init__(self, userKey):
        print(f"Initializing Serpent with key: {userKey}")
        self.encryptor = SerpentEncryptor(userKey)
        self.decryptor = SerpentDecryptor(userKey)

    def xor_bitstrings(self, bitstring1, bitstring2):
        try:
            assert len(bitstring1) == len(bitstring2) == 128
            return ''.join(str(int(a) ^ int(b)) for a, b in zip(bitstring1, bitstring2))
        except Exception as e:
            print(f"XOR Error: {e}")
            return None

    def encrypt_cbc(self, plaintext, iv):
        try:
            # Encode plaintext to bytes and apply padding
            padded_plaintext = pkcs7_padding(plaintext.encode('utf-8'))
            print(f"Padded plaintext: {padded_plaintext}")
            blocks = [padded_plaintext[i:i + 16] for i in range(0, len(padded_plaintext), 16)]
            print(f"Blocks: {blocks}")

            iv_bitstring = hexstring2bitstring(iv.hex())
            print(f"IV Bitstring: {iv_bitstring}")
            encrypted_blocks = []

            for block in blocks:
                block_bitstring = hexstring2bitstring(block.hex())
                print(f"Block Bitstring: {block_bitstring}")
                xor_block = self.xor_bitstrings(iv_bitstring, block_bitstring)
                if xor_block is None:
                    print("Encryption XOR returned None")
                    return None
                encrypted_block_hex = self.encryptor.encrypt(bitstring2hexstring(xor_block))
                print(f"Encrypted Block Hex: {encrypted_block_hex}")
                if encrypted_block_hex is None:
                    print("Encryptor returned None")
                    return None
                encrypted_blocks.append(encrypted_block_hex)
                iv_bitstring = hexstring2bitstring(encrypted_block_hex)

            return ''.join(encrypted_blocks)
        except Exception as e:
            print(f"Encryption Error: {e}")
            return None

    def decrypt_cbc(self, ciphertext, iv):
        try:
            blocks = [ciphertext[i:i + 32] for i in range(0, len(ciphertext), 32)]
            print(f"Ciphertext Blocks: {blocks}")

            iv_bitstring = hexstring2bitstring(iv.hex())
            print(f"IV Bitstring: {iv_bitstring}")
            decrypted_blocks = []

            for block in blocks:
                decrypted_block_hex = self.decryptor.decrypt(block)
                print(f"Decrypted Block Hex: {decrypted_block_hex}")
                if decrypted_block_hex is None:
                    print("Decryptor returned None")
                    return None
                decrypted_block_bitstring = hexstring2bitstring(decrypted_block_hex)
                xor_block = self.xor_bitstrings(iv_bitstring, decrypted_block_bitstring)
                if xor_block is None:
                    print("Decryption XOR returned None")
                    return None
                decrypted_blocks.append(bitstring2hexstring(xor_block))
                iv_bitstring = hexstring2bitstring(block)

            decrypted_data = b''.join([bytes.fromhex(block) for block in decrypted_blocks])
            return pkcs7_unpadding(decrypted_data).decode('utf-8')
        except Exception as e:
            print(f"Decryption Error: {e}")
            return None

