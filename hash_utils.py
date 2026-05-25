
import os
import struct
import time
from Crypto.Hash import SHA256


def sha256_hash(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def _simple_compression(state: bytes, block: bytes) -> bytes:
    """Simplified compression function for the Merkle-Damgard demo."""
    return sha256_hash(state + block)


def merkle_damgard_demo():
    """
    Walks through how the Merkle-Damgard construction works step by step.
    Uses a simplified compression function (not the real SHA-256 internals).
    """
    print("Merkle-Damgard Construction:")
    print()
    print("  IV -> compress(H0, M1) -> compress(H1, M2) -> ... -> Hash")
    print()

    message = b"Merkle-Damgard construction demo for Advanced Cryptography course!"
    block_size = 64  # SHA-256 block size

    print(f"Message: \"{message.decode()}\"")
    print(f"Length: {len(message)} bytes")
    print()

    msg_len = len(message)
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % block_size != 56:
        padded.append(0x00)
    padded += struct.pack(">Q", msg_len * 8)

    print(f"Step 1 - Padding: {len(padded)} bytes ({len(padded) // block_size} blocks)")
    iv = bytes.fromhex(
        "6a09e667bb67ae853c6ef372a54ff53a"
        "510e527f9b05688c1f83d9ab5be0cd19"
    )
    state = iv
    print(f"Step 2 - IV: {iv.hex()[:32]}...")

    blocks = [bytes(padded[i:i + block_size]) for i in range(0, len(padded), block_size)]
    print(f"Step 3 - Processing {len(blocks)} block(s):")
    for i, block in enumerate(blocks):
        prev_state = state
        state = _simple_compression(state, block)
        print(f"  Block {i+1}: H_{i} -> compress -> H_{i+1} = {state.hex()[:16]}...")

    print(f"Step 4 - Simulated hash: {state.hex()}")

    real_hash = sha256_hash(message)
    print(f"Real SHA-256 hash:       {real_hash.hex()}")
    print()
    print("Note: simulated hash differs because we used SHA256(state||block)")
    print("as compression, not the actual SHA-256 compression function.")
    print("The point is to show the structure.")

    return state


def commit(message: bytes, nonce: bytes) -> bytes:
    """commitment = SHA-256(message || nonce)"""
    return SHA256.new(message + nonce).digest()


def verify_commitment(message: bytes, nonce: bytes, commitment: bytes) -> bool:
    return commit(message, nonce) == commitment


def benchmark_hash(sizes=None, iterations=1000):
    """Time SHA-256 for different input sizes."""
    if sizes is None:
        sizes = [16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576]

    results = []
    print(f"{'Size':>12}  {'Avg Time':>12}  {'Throughput':>14}")

    for size in sizes:
        data = os.urandom(size)

        for _ in range(10):
            sha256_hash(data)

        start = time.perf_counter()
        for _ in range(iterations):
            sha256_hash(data)
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / iterations) * 1000
        throughput = (size / (1024 * 1024)) / (elapsed / iterations) if elapsed > 0 else 0

        if size >= 1048576:
            label = f"{size // 1048576} MB"
        elif size >= 1024:
            label = f"{size // 1024} KB"
        else:
            label = f"{size} B"

        print(f"{label:>12}  {avg_ms:>10.4f} ms  {throughput:>10.2f} MB/s")
        results.append((size, avg_ms, throughput))

    return results


if __name__ == "__main__":
    print("Hash Functions Demo")
    print()

    test_msgs = [b"Hello, World!", b"Hello, World!", b"Hello, World", b""]
    for msg in test_msgs:
        d = sha256_hash(msg)
        print(f"SHA-256(\"{msg.decode()}\") = {d.hex()[:32]}...")

    assert sha256_hash(b"test") == sha256_hash(b"test")
    print("SHA-256 is deterministic")

    h1 = sha256_hash(b"Hello, World!")
    h2 = sha256_hash(b"Hello, World")
    diff_bits = sum(bin(a ^ b).count('1') for a, b in zip(h1, h2))
    print(f"Avalanche: 1-byte change flips {diff_bits}/256 bits ({diff_bits/256*100:.1f}%)")
    print()

    merkle_damgard_demo()
    print()

    print("Commitment Scheme:")
    secret = b"I predict the coin will land on heads."
    nonce = os.urandom(32)
    c = commit(secret, nonce)
    print(f"Message: \"{secret.decode()}\"")
    print(f"Nonce:   {nonce.hex()[:32]}...")
    print(f"Commit:  {c.hex()}")

    assert verify_commitment(secret, nonce, c) is True
    assert verify_commitment(b"wrong message", nonce, c) is False
    assert verify_commitment(secret, os.urandom(32), c) is False
    print("Verify correct: True, wrong msg: False, wrong nonce: False")
    print()


    print("SHA-256 Benchmarks:")
    benchmark_hash()
    print()
    print("All hash tests passed.")
