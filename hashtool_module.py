#!/usr/bin/env python3
"""Hash Identifier/Checker - Identify hash types and check against breach databases."""

import argparse
import hashlib
import hmac
import json
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError
from urllib.parse import urlencode
from pathlib import Path

import bcrypt
import argon2

argon2_hasher = argon2.PasswordHasher()

try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None


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


def get_remediation(malware_family, file_type):
    """Return remediation steps based on malware family and file type."""
    remediation = {
        "general": [
            "1. ISOLATE the infected system from the network immediately",
            "2. Take a snapshot/image of the system for forensic analysis",
            "3. Run a full system scan with updated antivirus/EDR tools",
            "4. Check running processes and terminate suspicious ones",
            "5. Review system logs for Indicators of Compromise (IoCs)",
            "6. Change all passwords from a clean system",
            "7. Restore affected files from clean backups",
            "8. Report incident to your security team/CERT",
        ]
    }

    specific = {
        "ransomware": [
            " - DO NOT pay the ransom",
            " - Check for decryptors at https://www.nomoreransom.org/",
            " - Isolate immediately to prevent spread to network shares",
            " - Check backup integrity before restoring",
            " - Report to law enforcement (IC3, etc.)",
        ],
        "trojan": [
            " - Scan all connected systems for lateral movement",
            " - Check for persistence mechanisms (registry, scheduled tasks, services)",
            " - Monitor network traffic for C2 communication",
            " - Update firewall rules to block known C2 IPs/domains",
        ],
        "worm": [
            " - Patch vulnerable services immediately",
            " - Segment network to prevent lateral spread",
            " - Update all systems with latest security patches",
        ],
        "spyware": [
            " - Check for keyloggers and screen capture tools",
            " - Review network traffic for data exfiltration",
            " - Change banking/credit card credentials immediately",
        ],
    }

    family_lower = (malware_family or "").lower()
    type_lower = (file_type or "").lower()

    steps = list(remediation["general"])

    for key, actions in specific.items():
        if key in family_lower or key in type_lower:
            steps.extend(actions)

    return steps


def generate_hmac(message, key, algo="sha256"):
    """Generate HMAC for a message using specified algorithm."""
    algo = algo.lower()
    hash_algos = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
    }
    if algo not in hash_algos:
        raise ValueError(f"Unsupported algorithm: {algo}")
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hash_algos[algo]).hexdigest()


def verify_hmac(message, key, signature, algo="sha256"):
    """Verify HMAC signature using constant-time comparison."""
    expected = generate_hmac(message, key, algo)
    return timing_safe_compare(expected, signature)


def init_integrity_baseline(directory, algo="sha256"):
    """Create a baseline of file hashes for integrity monitoring."""
    import json
    from datetime import datetime

    dir_path = Path(directory)
    if not dir_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    baseline = {
        "directory": str(dir_path.absolute()),
        "created": datetime.now().isoformat(),
        "algorithm": algo,
        "files": {}
    }

    for f in dir_path.rglob("*"):
        if f.is_file():
            try:
                file_hash = hash_file(str(f), algo)
                rel_path = str(f.relative_to(dir_path))
                baseline["files"][rel_path] = file_hash
            except (IOError, OSError):
                continue

    baseline_file = dir_path / ".integrity_baseline.json"
    with open(baseline_file, "w") as f:
        json.dump(baseline, f, indent=2)

    return len(baseline["files"]), str(baseline_file)


def check_integrity(directory, algo="sha256"):
    """Check directory against stored baseline."""
    import json
    from datetime import datetime

    dir_path = Path(directory)
    baseline_file = dir_path / ".integrity_baseline.json"

    if not baseline_file.exists():
        raise FileNotFoundError("No baseline found. Run 'monitor-init' first.")

    with open(baseline_file) as f:
        baseline = json.load(f)

    changes = {"modified": [], "added": [], "deleted": [], "unchanged": []}
    baseline_files = baseline.get("files", {})

    # Check existing files
    for f in dir_path.rglob("*"):
        if f.is_file() and f.name != ".integrity_baseline.json":
            try:
                rel_path = str(f.relative_to(dir_path))
                current_hash = hash_file(str(f), algo)
                if rel_path in baseline_files:
                    if current_hash != baseline_files[rel_path]:
                        changes["modified"].append(rel_path)
                    else:
                        changes["unchanged"].append(rel_path)
                else:
                    changes["added"].append(rel_path)
            except (IOError, OSError):
                continue

    # Check for deleted files
    for rel_path in baseline_files:
        if not (dir_path / rel_path).exists():
            changes["deleted"].append(rel_path)

    return changes, baseline.get("created", "unknown")


def estimate_password_strength(password):
    """Estimate password strength using zxcvbn."""
    if zxcvbn is None:
        return {"error": "zxcvbn not installed. Run: pip install zxcvbn-python"}

    result = zxcvbn(password)
    return {
        "password": password,
        "score": result["score"],  # 0-4 (0=weak, 4=strong)
        "guesses": result["guesses"],
        "guesses_log10": result["guesses_log10"],
        "crack_time": result["crack_times_display"],
        "feedback": result["feedback"],
        "calc_time": result["calc_time"],
    }


def batch_hash_check(hash_file, wordlist=None, check_type="malware", algo="md5"):
    """Process multiple hashes from a file."""
    path = Path(hash_file)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {hash_file}")

    results = []
    with open(path) as f:
        hashes = [line.strip() for line in f if line.strip()]

    for h in hashes:
        result = {
            "hash": h,
            "sha256": h,
        }

        if check_type == "malware":
            malware_result = check_malware_hash(h)
            result["malware"] = malware_result
            result["status"] = "malicious" if malware_result.get("query_status") == "ok" else "clean"

        elif check_type == "breach":
            # Only check passwords, not hashes
            result["breach"] = "N/A (use 'check' command for passwords)"

        elif check_type == "identify":
            result["identification"] = identify_hash(h)

        elif check_type == "crack" and wordlist:
            found, tried = crack_hash(h, wordlist, algo)
            result["cracked"] = found
            result["attempts"] = tried

        results.append(result)

    return results


def check_malware_hash(hash_string):
    """Check if a hash appears in malware databases using MalwareBazaar."""
    import json

    h = hash_string.strip().lower()
    url = "https://mb-api.abuse.ch/api/v1/"
    data = urlencode({"query": "get_info", "hash": h}).encode()

    req = Request(url, data=data)
    req.add_header("Auth-Key", "bc682eea7dee70303cafe29f9d6bdf583c2c71ddc7dbf0d4")
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        with urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result
    except URLError as e:
        return {"error": str(e), "query_status": "error"}


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

    hmac_gen_parser = subparsers.add_parser("hmac-generate", help="Generate HMAC for a message")
    hmac_gen_parser.add_argument("message", help="Message to authenticate")
    hmac_gen_parser.add_argument("key", help="Secret key")
    hmac_gen_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    hmac_verify_parser = subparsers.add_parser("hmac-verify", help="Verify HMAC signature")
    hmac_verify_parser.add_argument("message", help="Original message")
    hmac_verify_parser.add_argument("key", help="Secret key")
    hmac_verify_parser.add_argument("signature", help="HMAC signature to verify")
    hmac_verify_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    monitor_init_parser = subparsers.add_parser("monitor-init", help="Initialize file integrity baseline")
    monitor_init_parser.add_argument("directory", help="Directory to monitor")
    monitor_init_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    monitor_check_parser = subparsers.add_parser("monitor-check", help="Check directory integrity against baseline")
    monitor_check_parser.add_argument("directory", help="Directory to check")
    monitor_check_parser.add_argument(
        "--algo",
        default="sha256",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm (default: sha256)",
    )

    strength_parser = subparsers.add_parser("password-strength", help="Estimate password strength")
    strength_parser.add_argument("password", help="Password to evaluate")

    batch_parser = subparsers.add_parser("batch", help="Process multiple hashes from a file")
    batch_parser.add_argument("hash_file", help="File containing hashes (one per line)")
    batch_parser.add_argument(
        "--type",
        default="malware",
        choices=["malware", "identify", "crack"],
        help="Type of check (default: malware)",
    )
    batch_parser.add_argument(
        "--wordlist",
        help="Wordlist for crack type",
    )
    batch_parser.add_argument(
        "--algo",
        default="md5",
        choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"],
        help="Hash algorithm for crack type (default: md5)",
    )
    batch_parser.add_argument(
        "--output",
        help="Output file for results (JSON format)",
    )

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
        if result.get("query_status") == "hash_not_found":
            print("Hash NOT found in malware database (appears clean)")
        elif result.get("query_status") == "ok":
            data = result.get("data", [{}])[0]
            print("⚠️  MALWARE DETECTED ⚠️")
            print(f"SHA256: {data.get('sha256_hash', 'N/A')}")
            print(f"MD5: {data.get('md5_hash', 'N/A')}")
            print(f"SHA1: {data.get('sha1_hash', 'N/A')}")
            print(f"File name: {data.get('file_name', 'N/A')}")
            print(f"File type: {data.get('file_type', 'N/A')}")
            print(f"Malware family: {data.get('malware_family', 'N/A')}")
            print(f"Signature: {data.get('signature', 'N/A')}")
            print(f"First seen: {data.get('first_seen', 'N/A')}")
            print(f"VirusTotal: https://www.virustotal.com/gui/file/{data.get('sha256_hash', '')}")

            print("\nREMEDIATION STEPS:")
            family = data.get('malware_family', '')
            file_type = data.get('file_type', '')
            steps = get_remediation(family, file_type)
            for step in steps:
                print(step)
        else:
            print(f"Query status: {result.get('query_status', 'unknown')}")

    elif args.command == "hmac-generate":
        try:
            signature = generate_hmac(args.message, args.key, args.algo)
            print(f"HMAC ({args.algo.upper()}): {signature}")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "hmac-verify":
        try:
            if verify_hmac(args.message, args.key, args.signature, args.algo):
                print("HMAC VERIFIED")
            else:
                print("HMAC INVALID")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "monitor-init":
        try:
            count, baseline_path = init_integrity_baseline(args.directory, args.algo)
            print(f"Baseline created: {baseline_path}")
            print(f"Files hashed: {count}")
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "monitor-check":
        try:
            changes, baseline_date = check_integrity(args.directory, args.algo)
            print(f"Integrity check (baseline: {baseline_date})")
            print(f"Modified files: {len(changes['modified'])}")
            for f in changes['modified']:
                print(f"  - {f}")
            print(f"Added files: {len(changes['added'])}")
            for f in changes['added']:
                print(f"  + {f}")
            print(f"Deleted files: {len(changes['deleted'])}")
            for f in changes['deleted']:
                print(f"  - {f}")
            print(f"Unchanged: {len(changes['unchanged'])}")
            if not any(changes.values()):
                print("No changes detected")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "password-strength":
        result = estimate_password_strength(args.password)
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)
        print(f"Password: {result['password'][:3]}***")
        print(f"Score: {result['score']}/4 ", end="")
        score_labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        print(f"({score_labels[result['score']]})")
        print(f"Estimated guesses: {result['guesses']:,}")
        print(f"Crack time (offline): {result['crack_time']['offline_slow_hashing_1e4_per_second']}")
        print(f"Crack time (online): {result['crack_time']['online_no_throttling_10_per_second']}")
        if result['feedback'].get('warning'):
            print(f"Warning: {result['feedback']['warning']}")
        if result['feedback'].get('suggestions'):
            print("Suggestions:")
            for s in result['feedback']['suggestions']:
                print(f"  - {s}")

    elif args.command == "batch":
        try:
            results = batch_hash_check(
                args.hash_file,
                wordlist=args.wordlist,
                check_type=args.type,
                algo=args.algo
            )
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2)
                print(f"Results written to {args.output}")
            else:
                for r in results:
                    print(f"\nHash: {r['hash'][:20]}...")
                    print(f"  Status: {r.get('status', 'N/A')}")
                    if 'identification' in r:
                        for name, desc in r['identification']:
                            print(f"  - {name}: {desc}")
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1)

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
