"""Manual decryptor: paste the granted key, get your files back.

The exchange granted a decryption key after the ransom was paid (option 5 in
the participant menu printed it). This is the victim's hands-on recovery step,
like the decryptors real ransomware victims ran:

  1. Paste the AES-256 file key you were granted.
  2. Every envelope is decrypted with that key (AES-256-GCM); its integrity
     tag must verify before ANY file is written. Originals are restored under
     their names and the envelopes are deleted.

Nothing is automatic: without the key pasted here, no file comes back.
"""

import argparse
import base64

from software.ransomware.runtime.engine import Ransomware


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key", default=None,
                        help="the decryption key you were granted (b64); omitted = prompt for it")
    args = parser.parse_args(argv)
    rw = Ransomware()

    print("=" * 60)
    print(f"  {rw.family.upper()} LAB DECRYPTOR")
    print("  Paste the decryption key the attacker granted you.")
    print("=" * 60)

    pasted = args.key or input("Paste your decryption key: ").strip()
    try:
        file_key = base64.b64decode(pasted.encode("ascii"), validate=True)
    except Exception:
        raise SystemExit("that is not valid base64; copy the key exactly as printed")
    if len(file_key) != 32:
        raise SystemExit(
            f"expected a 32-byte AES-256 key (got {len(file_key)} bytes); "
            "copy the full key exactly as printed"
        )
    print()
    print("Decrypting with the pasted key:")
    try:
        rw.recover(file_key)
    except Exception as error:  # InvalidTag carries no message
        name = type(error).__name__
        raise SystemExit(f"\nDecryption failed ({name}): wrong key or tampered file. "
                         "No file was restored.")
    print()
    print("All ransomware envelopes removed. Your documents are back.")
    return 0


if __name__ == "__main__":
    main()
