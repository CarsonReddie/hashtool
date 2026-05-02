#!/usr/bin/env python3
"""Hash Identifier/Checker - Identify hash types and check against breach databases."""

import argparse
import hashlib
import hmac
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlencode
from pathlib import Path

import bcrypt
import argon2

argon2_hasher = argon2.PasswordHasher()


def identify_hash(hash_string):
    """Identify the likely type of a given hash."""
    h = hash_string.strip()
    results = []

    patterns = [
        (r"^\$2[ayb]\$\d+\$.+", "bcrypt", "bcrypt (starting with $2a$, $2b$, or $2y$)"),
        (r"^\$s0\$\d+\$\$.+", "scrypt", "scrypt (OpenSSL format)"),
        (r"^\$scrypt\$.+", "scrypt", "scrypt"),
        (r"^\$argon2[a-z]*\$", "Argon2", "Argon2"),
        (r"^[a-fA-F0-9]{32}$", "MD5", "32 hex chars"),
        (r"^[a-fA-F0-9]{40}$", "SHA1", "40 hex chars"),
        (r"^[a-fA-F0-9]{64}$", "SHA256", "64 hex chars"),
        (r"^[a-fA-F0-9]{128}$", "SHA512", "128 hex chars"),
        (r"^[a-fA-F0-9]{56}$", "SHA224", "56 hex chars"),
        (r"^[a-fA-F0-9]{96}$", "SHA384", "96 hex chars"),
        (r"^[A-Za-z0-9+/]{24}={0,2}$", "bcrypt (base64)", "Possible bcrypt base64"),
        (r"^[A-Za-z0-9+/]{43}=$", "SHA256 (base64)", "Possible SHA256 base64"),
        (r"^[A-Za-z0-9+/]{28}=$", "SHA224 (base64)", "Possible SHA224 base64"),
    ]

    for pattern, name, desc in patterns:
        if re.match(pattern, h):
            results.append((name, desc))

    if re.match(r"^[A-F0-9]{32}$", h) and not re.match(r"^[a-f0-9]{32}$", h):
        results.append(("NTLM", "32 uppercase hex chars"))

    if not results:
        results.append(("Unknown", f"Length: {len(h)} chars, Charset: {get_charset(h)}"))

    return results


def get_charset(s):
    chars = set(s)
    parts = []
    if any(c in "abcdef" for c in chars) and any(c in "ABCDEF" for c in chars):
        parts.append("mixed hex")
    elif any(c in "abcdef" for c in chars):
        parts.append("lowercase hex")
    elif any(c in "ABCDEF" for c in chars):
        parts.append("uppercase hex")
    if any(c.isdigit() for c in chars):
        parts.append("digits")
    if any(c in "+/=" for c in chars):
        parts.append("base64")
    return ", ".join(parts) if parts else "unknown"


def check_malware_hash(hash_string):
    """Check if a hash appears in malware databases using CIRCL HashLookup."""
    import json

    h = hash_string.strip().lower()
    url = f"https://hashlookup.circl.lu/lookup/{h}"
    req = Request(url, headers={"User-Agent": "hashtool/1.0", "Accept": "application/json"})

    try:
        with urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result
    except URLError as e:
        if "404" in str(e) or "NOT FOUND" in str(e).upper():
            return {"message": "hash not found"}
        return {"error": str(e)}


def sha1_hash(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def check_breach(password):
    """Check password against HaveIBeenPwned using k-anonymity."""
    sha1 = sha1_hash(password)
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = Request(url, headers={"User-Agent": "hashtool/1.0"})

    try:
        with urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
    except URLError as e:
        return None, f"Network error: {e}"

    for line in data.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1]), None

    return 0, None


def hash_password(password, method="bcrypt"):
    """Hash a password using bcrypt or Argon2."""
    password_bytes = password.encode("utf-8")
    if method == "bcrypt":
        return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")
    elif method == "argon2":
        return argon2_hasher.hash(password)
    else:
        raise ValueError(f"Unsupported method: {method}")


def verify_password(password, hashed):
    """Verify a password against a bcrypt or Argon2 hash."""
    password_bytes = password.encode("utf-8")
    hashed_str = hashed if isinstance(hashed, str) else hashed.decode("utf-8")
    if hashed_str.startswith(("$2a$", "$2b$", "$2y$")):
        return bcrypt.checkpw(password_bytes, hashed.encode("utf-8"))
    elif hashed_str.startswith("$argon2"):
        try:
            argon2_hasher.verify(hashed_str, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
    else:
        raise ValueError("Unknown hash format")


def timing_safe_compare(hash1, hash2):
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(
        hash1 if isinstance(hash1, bytes) else hash1.encode("utf-8"),
        hash2 if isinstance(hash2, bytes) else hash2.encode("utf-8"),
    )


def crack_hash(hash_string, wordlist_path, hash_type="md5"):
    """Simulate dictionary attack against a hash (educational purposes)."""
    hash_type = hash_type.lower()
    path = Path(wordlist_path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }

    if hash_type not in hash_funcs:
        raise ValueError(f"Unsupported hash type: {hash_type}")

    target = hash_string.lower().strip()
    tried = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            tried += 1
            h = hash_funcs[hash_type](word.encode("utf-8")).hexdigest()
            if timing_safe_compare(h, target):
                return word, tried

    return None, tried


def generate_hash(text, algo="sha256"):
    """Generate hash from text using specified algorithm."""
    algo = algo.lower()
    if algo == "md5":
        return hashlib.md5(text.encode("utf-8")).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(text.encode("utf-8")).hexdigest()
    elif algo == "sha224":
        return hashlib.sha224(text.encode("utf-8")).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    elif algo == "sha384":
        return hashlib.sha384(text.encode("utf-8")).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(text.encode("utf-8")).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")


def hash_file(filepath, algo="sha256"):
    """Compute hash of a file using specified algorithm."""
    algo = algo.lower()
    try:
        h = getattr(hashlib, algo)()
    except AttributeError:
        raise ValueError(f"Unsupported algorithm: {algo}")

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash_breach(hash_string):
    """Check if a hash appears in breach databases."""
    return identify_hash(hash_string), hash_string


def main():
    parser = argparse.ArgumentParser(
        description="Hash Identifier/Checker - Identify hash types and check breaches"
    )
    subparsers = parser.add_subparsers(dest="command")

    identify_parser = subparsers.add_parser("identify", help="Identify hash type")
    identify_parser.add_argument("hash", help="Hash string to identify")

    check_parser = subparsers.add_parser("check", help="Check if password was breached")
    check_parser.add_argument("password", help="Password to check")

    check_hash_parser = subparsers.add_parser("check-hash", help="Get info about a hash")
    check_hash_parser.add_argument("hash", help="Hash to analyze")

    malware_parser = subparsers.add_parser("malware-check", help="Check hash against malware databases")
    malware_parser.add_argument("hash", help="Hash to check (MD5, SHA1, or SHA256)")

    gen_parser = subparsers.add_parser("generate", help="Generate hash from text")
    gen_parser.add_argument("text", help="Text to hash")
    gen_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    file_parser = subparsers.add_parser("file", help="Hash a file")
    file_parser.add_argument("filepath", help="Path to file")
    file_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    hashpw_parser = subparsers.add_parser("hash-password", help="Hash a password with bcrypt/Argon2")
    hashpw_parser.add_argument("password", help="Password to hash")
    hashpw_parser.add_argument(
        "--method",
        default="bcrypt",
        choices=["bcrypt", "argon2"],
        help="Hashing method (default: bcrypt)",
    )

    verify_parser = subparsers.add_parser("verify", help="Verify password against hash")
    verify_parser.add_argument("password", help="Password to verify")
    verify_parser.add_argument("hash", help="Hash to verify against")

    crack_parser = subparsers.add_parser("crack", help="Dictionary attack simulation (educational)")
    crack_parser.add_argument("hash", help="Hash to crack")
    crack_parser.add_argument("wordlist", help="Path to wordlist file")
    crack_parser.add_argument(
        "--type",
        default="md5",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash type (default: md5)",
    )

    args = parser.parse_args()

    if args.command == "identify":
        results = identify_hash(args.hash)
        print(f"Hash: {args.hash[:20]}...")
        print("Possible types:")
        for name, desc in results:
            print(f"  - {name}: {desc}")

    elif args.command == "check":
        count, err = check_breach(args.password)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        if count > 0:
            print(f"PASSWORD COMPROMISED - found in {count:,} breaches")
        else:
            print("Password not found in known breaches")

    elif args.command == "check-hash":
        results = identify_hash(args.hash)
        print(f"Hash: {args.hash}")
        print("Identified as:")
        for name, desc in results:
            print(f"  - {name}: {desc}")

    elif args.command == "malware-check":
        result = check_malware_hash(args.hash)
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        if "message" in result and "not found" in result.get("message", "").lower():
            print("Hash NOT found in malware database")
        elif "KnownMalicious" in result or result.get("tag") == "malicious":
            print("⚠️  MALWARE DETECTED ⚠️")
            print(f"Hash: {args.hash}")
            if "SHA1" in result:
                print(f"SHA1: {result.get('SHA1')}")
            if "MD5" in result:
                print(f"MD5: {result.get('MD5')}")
            if "filename" in result:
                print(f"Filename: {result.get('filename')}")
            if "KnownMalicious" in result:
                print(f"Malicious: {result.get('KnownMalicious')}")
        else:
            print("Hash NOT found in malware database (appears clean)")

    elif args.command == "generate":
        try:
            result = generate_hash(args.text, args.algo)
            print(f"{args.algo.upper()}: {result}")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "file":
        try:
            result = hash_file(args.filepath, args.algo)
            print(f"{args.algo.upper()} ({args.filepath}): {result}")
        except (ValueError, FileNotFoundError) as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "hash-password":
        try:
            result = hash_password(args.password, args.method)
            print(f"Hashed ({args.method}): {result}")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "verify":
        try:
            if verify_password(args.password, args.hash):
                print("Password VERIFIED")
            else:
                print("Password INVALID")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "crack":
        try:
            result, tried = crack_hash(args.hash, args.wordlist, args.type)
            if result:
                print(f"Password FOUND: {result}")
                print(f"Attempts: {tried:,}")
            else:
                print(f"Password not found after {tried:,} attempts")
        except (ValueError, FileNotFoundError) as e:
            print(f"Error: {e}")
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
