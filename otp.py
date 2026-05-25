

import secrets


def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != len(plaintext):
        raise ValueError("Key length must equal plaintext length.")
    return bytes(p ^ k for p, k in zip(plaintext, key))


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != len(ciphertext):
        raise ValueError("Key length must equal ciphertext length.")
    return bytes(c ^ k for c, k in zip(ciphertext, key))


def generate_key(length: int) -> bytes:
    return secrets.token_bytes(length)


def derive_fake_key(ciphertext: bytes, fake_message: bytes) -> bytes:
    """Given a ciphertext, find a key that decrypts it to fake_message."""
    if len(ciphertext) != len(fake_message):
        raise ValueError("Ciphertext and fake message must have the same length.")
    # k' = c XOR m'
    return bytes(c ^ f for c, f in zip(ciphertext, fake_message))


if __name__ == "__main__":
    print("OTP Demo")
    print()


    message = b"Hello, Advanced Cryptography!"
    key = generate_key(len(message))
    ciphertext = otp_encrypt(message, key)
    decrypted = otp_decrypt(ciphertext, key)

    print(f"Plaintext : {message}")
    print(f"Key (hex) : {key.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted : {decrypted}")
    assert decrypted == message
    print("Round-trip OK")
    print()

    ct1 = otp_encrypt(message, key)
    ct2 = otp_encrypt(message, key)
    print(f"CT1: {ct1.hex()}")
    print(f"CT2: {ct2.hex()}")
    assert ct1 == ct2
    print("Same key produces same ciphertext")
    print()

    key2 = generate_key(len(message))
    ct3 = otp_encrypt(message, key2)
    assert ct1 != ct3
    print("Different key produces different ciphertext")
    print()

    print("Perfect Secrecy (Shannon's theorem):")
    print("For any ciphertext c and any message m', there exists")
    print("a key k' such that Dec(c, k') = m'.")
    print()

    real_message = b"Attack at dawn!!"
    real_key = generate_key(len(real_message))
    ciphertext = otp_encrypt(real_message, real_key)

    fake_message = b"Nothing to see."
    fake_message_padded = fake_message.ljust(len(real_message), b"\x00")[:len(real_message)]
    fake_key = derive_fake_key(ciphertext, fake_message_padded)
    decrypted_with_fake_key = otp_decrypt(ciphertext, fake_key)

    print(f"Real message    : {real_message}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Fake message    : {fake_message_padded}")
    print(f"Fake key (hex)  : {fake_key.hex()}")
    print(f"Decrypted w/fake: {decrypted_with_fake_key}")
    assert decrypted_with_fake_key == fake_message_padded
    print("Same ciphertext maps to a different message with a different key.")
    print()
    print("All OTP tests passed.")
