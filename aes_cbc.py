

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Empty data.")
    padding_len = data[-1]
    if padding_len == 0 or padding_len > 16:
        raise ValueError(f"Invalid padding byte: {padding_len}")
    if len(data) < padding_len:
        raise ValueError("Data shorter than padding length.")
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError(f"Bad padding at position -{i}")
    return data[:-padding_len]


def aes_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-CBC. Returns IV || ciphertext."""
    iv = get_random_bytes(16)
    padded = pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-CBC. Expects IV || ciphertext."""
    if len(ciphertext) < 32:
        raise ValueError("Ciphertext too short.")
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    if len(ct) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16.")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_plaintext = cipher.decrypt(ct)
    return pkcs7_unpad(padded_plaintext)


def padding_oracle(ciphertext: bytes, key: bytes) -> bool:
    """Returns True if decryption has valid padding, False otherwise."""
    try:
        if len(ciphertext) < 32 or len(ciphertext[16:]) % 16 != 0:
            return False
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ct)
        pkcs7_unpad(padded_plaintext)
        return True
    except (ValueError, KeyError):
        return False


if __name__ == "__main__":
    print("AES-CBC Demo")
    print()

    key = get_random_bytes(16)  # AES-128
    print(f"AES Key (hex): {key.hex()}")
    print()


    message = b"Hello, AES-CBC with PKCS#7 padding!"
    ciphertext = aes_cbc_encrypt(message, key)
    decrypted = aes_cbc_decrypt(ciphertext, key)

    print(f"Plaintext : {message}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"CT length : {len(ciphertext)} bytes (16 IV + {len(ciphertext)-16} encrypted)")
    print(f"Decrypted : {decrypted}")
    assert decrypted == message
    print("Round-trip OK")
    print()

  
    ct1 = aes_cbc_encrypt(message, key)
    ct2 = aes_cbc_encrypt(message, key)
    print(f"CT1: {ct1.hex()}")
    print(f"CT2: {ct2.hex()}")
    print(f"IV1: {ct1[:16].hex()}")
    print(f"IV2: {ct2[:16].hex()}")
    assert ct1 != ct2
    print("Same plaintext gives different ciphertexts (random IV = CPA security)")
    print()

    print("PKCS#7 padding:")
    for msg in [b"A" * 1, b"B" * 15, b"C" * 16, b"D" * 31]:
        padded = pkcs7_pad(msg)
        unpadded = pkcs7_unpad(padded)
        print(f"  {len(msg):2d} bytes -> {len(padded):2d} bytes, pad=0x{padded[-1]:02x} ({padded[-1]} bytes)")
        assert unpadded == msg
    print()

    valid_ct = aes_cbc_encrypt(b"Test padding oracle", key)
    print(f"Valid ciphertext  -> oracle = {padding_oracle(valid_ct, key)}")

    tampered_ct = bytearray(valid_ct)
    tampered_ct[-1] ^= 0xFF
    tampered_ct = bytes(tampered_ct)
    print(f"Tampered ciphertext -> oracle = {padding_oracle(tampered_ct, key)}")

    assert padding_oracle(valid_ct, key) is True
    assert padding_oracle(tampered_ct, key) is False
    print()
    print("All AES-CBC tests passed.")
