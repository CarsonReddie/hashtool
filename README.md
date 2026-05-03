# Hashtool - Hash Identifier/Checker

A command-line tool for cybersecurity professionals to identify hash types, check against breach and malware databases, and perform secure cryptographic operations.

## Features

- **Hash Identification** - Identify hash types (MD5, SHA1, SHA256, SHA512, bcrypt, Argon2, NTLM, etc.)
- **Breach Checking** - Check passwords against HaveIBeenPwned using k-anonymity API
- **Malware Detection** - Check file hashes against MalwareBazaar database with remediation steps
- **Hash Generation** - Generate hashes using various algorithms (MD5, SHA1, SHA224, SHA256, SHA384, SHA512)
- **File Hashing** - Hash files for integrity verification
- **Secure Password Hashing** - Hash passwords with bcrypt and Argon2
- **Password Verification** - Verify passwords against secure hashes
- **HMAC Operations** - Generate and verify HMAC signatures for message authentication
- **File Integrity Monitor** - Track file changes over time with stored baselines
- **Hash Cracking Simulation** - Educational dictionary attack simulation with timing-safe comparison

## Installation

```bash
pip install bcrypt argon2-cffi
```

## Usage

### Hash Identification
```bash
python3 hashtool.py identify 5e884898da28047151d0e56f8dc6292764c7d2a3d7337554a1fcce1eac6e6b2c
```

### Password Breach Check
```bash
python3 hashtool.py check "password123"
```

### Malware Hash Check
```bash
python3 hashtool.py malware-check <hash>
# Returns malware info and remediation steps
```

### Generate Hash
```bash
python3 hashtool.py generate "hello world" --algo sha256
```

### Hash a File
```bash
python3 hashtool.py file /path/to/file --algo sha256
```

### Secure Password Hashing
```bash
python3 hashtool.py hash-password "mypassword" --method bcrypt
python3 hashtool.py hash-password "mypassword" --method argon2
```

### Verify Password
```bash
python3 hashtool.py verify "mypassword" "$2b$12$..."
```

### HMAC Operations
```bash
# Generate HMAC
python3 hashtool.py hmac-generate "message" "secret-key" --algo sha256

# Verify HMAC
python3 hashtool.py hmac-verify "message" "secret-key" <signature> --algo sha256
```

### File Integrity Monitor
```bash
# Initialize baseline
python3 hashtool.py monitor-init /path/to/directory

# Check for changes
python3 hashtool.py monitor-check /path/to/directory
# Shows: modified, added, deleted files
```

### Hash Cracking Simulation (Educational)
```bash
python3 hashtool.py crack <hash> wordlist.txt --type md5
```

## Running Tests

```bash
pip install pytest
pytest test_hashtool.py -v
```

## Author

Carson

## License

MIT
