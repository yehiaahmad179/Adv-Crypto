

import json
import secrets
from math import gcd
from sympy import isprime


def generate_prime(bits: int) -> int:
    """Generate a random prime with the given bit length."""
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))  # ensure correct bit length
        candidate |= 1                   # make it odd
        if isprime(candidate):
            return candidate


def generate_rsa_keys(bits: int = 512) -> dict:
    """Generate RSA keys with e=65537. Returns dict with n, e, d, p, q."""
    e = 65537

    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        while p == q:
            q = generate_prime(bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            break

    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q, 'bits': bits * 2}


def generate_vulnerable_rsa(bits: int = 512) -> dict:
    """Generate RSA keys with e=3 (vulnerable to cube root attack)."""
    e = 3

    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        while p == q:
            q = generate_prime(bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) == 1:
            d = pow(e, -1, phi)
            break

    return {'n': n, 'e': e, 'd': d, 'p': p, 'q': q, 'bits': bits * 2, 'vulnerable': True}


def rsa_encrypt(m: int, e: int, n: int) -> int:
    """c = m^e mod n"""
    if m < 0 or m >= n:
        raise ValueError(f"m must be in [0, n). Got m={m}")
    return pow(m, e, n)


def rsa_decrypt(c: int, d: int, n: int) -> int:
    """m = c^d mod n"""
    return pow(c, d, n)


def message_to_int(message: bytes) -> int:
    return int.from_bytes(message, byteorder='big')


def int_to_message(number: int, length: int = None) -> bytes:
    if length is None:
        length = max((number.bit_length() + 7) // 8, 1)
    return number.to_bytes(length, byteorder='big')


def export_public_key(n: int, e: int, filename: str = "public_key.json"):
    """Save public key (n, e) to JSON."""
    data = {'algorithm': 'RSA', 'n': str(n), 'e': e}
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Public key saved to {filename}")


def import_public_key(filename: str = "public_key.json") -> tuple:
    with open(filename, 'r') as f:
        data = json.load(f)
    return int(data['n']), data['e']


if __name__ == "__main__":
    print("RSA Demo")
    print()

    print("Generating RSA keys (512-bit primes)...")
    keys = generate_rsa_keys(bits=512)

    print(f"p ({keys['p'].bit_length()} bits): {str(keys['p'])[:40]}...")
    print(f"q ({keys['q'].bit_length()} bits): {str(keys['q'])[:40]}...")
    print(f"n ({keys['n'].bit_length()} bits): {str(keys['n'])[:40]}...")
    print(f"e: {keys['e']}")
    print(f"d ({keys['d'].bit_length()} bits): {str(keys['d'])[:40]}...")

    phi = (keys['p'] - 1) * (keys['q'] - 1)
    assert (keys['e'] * keys['d']) % phi == 1
    print("e * d = 1 (mod phi(n)) verified")
    print()

    message = b"RSA works!"
    m_int = message_to_int(message)
    c = rsa_encrypt(m_int, keys['e'], keys['n'])
    m_dec = rsa_decrypt(c, keys['d'], keys['n'])
    decrypted = int_to_message(m_dec, len(message))

    print(f"Plaintext: \"{message.decode()}\"")
    print(f"m = {m_int}")
    print(f"c = {str(c)[:40]}...")
    print(f"Decrypted: \"{decrypted.decode()}\"")
    assert decrypted == message
    print("Round-trip OK")
    print()

    export_public_key(keys['n'], keys['e'], "public_key.json")
    n_imp, e_imp = import_public_key("public_key.json")
    assert n_imp == keys['n'] and e_imp == keys['e']
    print("Import verified")
    print()

    print("Generating vulnerable RSA keys (e=3)...")
    vuln = generate_vulnerable_rsa(bits=512)
    print(f"n ({vuln['n'].bit_length()} bits): {str(vuln['n'])[:40]}...")
    print(f"e: {vuln['e']}")
    print()

    small_msg = b"Hi"
    m_small = message_to_int(small_msg)
    c_vuln = rsa_encrypt(m_small, vuln['e'], vuln['n'])

    print(f"Small message: \"{small_msg.decode()}\" (m = {m_small})")
    print(f"m^3 = {m_small ** 3}")
    print(f"m^3 < n? {m_small ** 3 < vuln['n']}")

    if m_small ** 3 < vuln['n']:
        print("Since m^3 < n, modular reduction does nothing.")
        print("Attacker can just take the cube root of c.")

        import sympy
        m_recovered = sympy.integer_nthroot(c_vuln, 3)[0]
        recovered_msg = int_to_message(m_recovered, len(small_msg))
        print(f"Cube root of c = {m_recovered} -> \"{recovered_msg.decode()}\"")
        assert recovered_msg == small_msg
        print("Message recovered without private key!")
    print()

    export_public_key(vuln['n'], vuln['e'], "vulnerable_public_key.json")

    m_dec_vuln = rsa_decrypt(c_vuln, vuln['d'], vuln['n'])
    assert m_dec_vuln == m_small
    print("Normal decryption also works")
    print()
    print("All RSA tests passed.")
