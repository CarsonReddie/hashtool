"""Unit tests for hashtool."""

import pytest
from pathlib import Path
from hashlib import md5, sha1, sha256

from hashtool_module import (
    identify_hash,
    generate_hash,
    hash_file,
    hash_password,
    verify_password,
    timing_safe_compare,
    crack_hash,
    sha1_hash,
    check_breach,
)


class TestIdentifyHash:
    def test_md5(self):
        results = identify_hash("5eb63bbbe01eeed093cb22bb8f5acdc3")
        assert any(name == "MD5" for name, _ in results)

    def test_sha1(self):
        results = identify_hash("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        assert any(name == "SHA1" for name, _ in results)

    def test_sha256(self):
        results = identify_hash("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        assert any(name == "SHA256" for name, _ in results)

    def test_sha512(self):
        h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        results = identify_hash(h)
        assert any(name == "SHA512" for name, _ in results)

    def test_bcrypt(self):
        results = identify_hash("$2b$12$r9B2rX7udFeyiOX46z5v6eCqqAWanAZrTcHTnxwWE74eRbeZBCviu")
        assert any(name == "bcrypt" for name, _ in results)

    def test_argon2(self):
        results = identify_hash("$argon2id$v=19$m=65536,t=3,p=4$szx24kgyvYXNvnHJ8YkDsw$9toE0/KqhIhUcEs9PTSqD1HtZY9/rNEFZd3LXgo9BR0")
        assert any(name == "Argon2" for name, _ in results)

    def test_ntlm(self):
        results = identify_hash("E10ADC3949BA59ABBE56E057F20F883E")
        assert any(name == "NTLM" for name, _ in results)

    def test_unknown(self):
        results = identify_hash("notahash123")
        assert any(name == "Unknown" for name, _ in results)


class TestGenerateHash:
    def test_md5(self):
        result = generate_hash("hello", "md5")
        assert result == "5d41402abc4b2a76b9719d911017c592"

    def test_sha256(self):
        result = generate_hash("hello", "sha256")
        expected = sha256("hello".encode()).hexdigest()
        assert result == expected

    def test_default_algo(self):
        result = generate_hash("test")
        assert len(result) == 64

    def test_invalid_algo(self):
        with pytest.raises(ValueError):
            generate_hash("test", "invalid")


class TestHashFile:
    def test_hash_file_sha256(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        result = hash_file(str(test_file), "sha256")
        expected = sha256("hello world".encode()).hexdigest()
        assert result == expected

    def test_hash_file_md5(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        result = hash_file(str(test_file), "md5")
        expected = md5("hello".encode()).hexdigest()
        assert result == expected

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            hash_file("/nonexistent/file.txt")

    def test_invalid_algo(self):
        with pytest.raises(ValueError):
            hash_file("/etc/passwd", "invalid")


class TestHashPassword:
    def test_bcrypt_hash(self):
        result = hash_password("mypassword", "bcrypt")
        assert result.startswith("$2b$")

    def test_argon2_hash(self):
        result = hash_password("mypassword", "argon2")
        assert result.startswith("$argon2")

    def test_invalid_method(self):
        with pytest.raises(ValueError):
            hash_password("test", "invalid")


class TestVerifyPassword:
    def test_bcrypt_verify_correct(self):
        hashed = hash_password("mypassword", "bcrypt")
        assert verify_password("mypassword", hashed) is True

    def test_bcrypt_verify_incorrect(self):
        hashed = hash_password("mypassword", "bcrypt")
        assert verify_password("wrongpassword", hashed) is False

    def test_argon2_verify_correct(self):
        hashed = hash_password("mypassword", "argon2")
        assert verify_password("mypassword", hashed) is True

    def test_argon2_verify_incorrect(self):
        hashed = hash_password("mypassword", "argon2")
        assert verify_password("wrongpassword", hashed) is False


class TestTimingSafeCompare:
    def test_equal_strings(self):
        assert timing_safe_compare("abc123", "abc123") is True

    def test_different_strings(self):
        assert timing_safe_compare("abc123", "def456") is False

    def test_bytes_comparison(self):
        assert timing_safe_compare(b"test", b"test") is True
        assert timing_safe_compare(b"test", b"fail") is False


class TestCrackHash:
    def test_crack_found(self, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("password\n123456\nadmin\nmypassword\n")
        target = md5("mypassword".encode()).hexdigest()
        result, tried = crack_hash(target, str(wordlist), "md5")
        assert result == "mypassword"
        assert tried == 4

    def test_crack_not_found(self, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("password\n123456\nadmin\n")
        target = md5("mypassword".encode()).hexdigest()
        result, tried = crack_hash(target, str(wordlist), "md5")
        assert result is None
        assert tried == 3

    def test_crack_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            crack_hash("abc", "/nonexistent/wordlist.txt")


class TestSha1Hash:
    def test_sha1_hash(self):
        result = sha1_hash("password123")
        assert len(result) == 40
        assert result.isupper()


class TestCheckBreach:
    def test_breached_password(self):
        count, err = check_breach("password123")
        assert err is None
        assert count > 0

    def test_safe_password(self):
        import uuid
        safe_password = str(uuid.uuid4()) + "VerySafe!"
        count, err = check_breach(safe_password)
        assert err is None
        assert count == 0
