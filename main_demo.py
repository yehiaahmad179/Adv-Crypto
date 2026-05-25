

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_module(module_name, filepath):
    print(f"--- {module_name} ---")
    print()
    try:
        exec(open(filepath).read(), {"__name__": "__main__"})
        print()
        return True
    except Exception as e:
        print(f"ERROR in {module_name}: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    print("Advanced Cryptography Project - Full Demo")
    print()

    base = os.path.dirname(os.path.abspath(__file__))
    modules = [
        ("OTP", os.path.join(base, "otp.py")),
        ("AES-CBC", os.path.join(base, "aes_cbc.py")),
        ("Hash Functions", os.path.join(base, "hash_utils.py")),
        ("RSA", os.path.join(base, "rsa.py")),
    ]

    results = []
    for name, path in modules:
        passed = run_module(name, path)
        results.append((name, passed))

    print("Summary:")
    for name, passed in results:
        status = "OK" if passed else "FAIL"
        print(f"  {name}: {status}")

    if all(p for _, p in results):
        print("\nAll modules passed.")
    else:
        print("\nSome modules failed.")


if __name__ == "__main__":
    main()
