#!/usr/bin/env python3
import argparse
import base64
import binascii
import datetime
import hmac
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


NAME = r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
NONCE = bytes(12)
STEPS = (256, 1024, 4096, 8192, 16384, 32768, 65536)
TAG_BYTES = 16
LARGEST_FILE = 1024 * 1024
LARGEST_PGP_WRAP = 4096


def decode64(text):
    data = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    if base64.b64encode(data).decode().rstrip("=") != text:
        raise ValueError("non-canonical base64")
    return data


def sealed(text):
    length = len(text) // 4 * 3 + max(len(text) % 4 - 1, 0)
    if length - TAG_BYTES not in STEPS:
        raise ValueError("invalid sealed length")
    return decode64(text)


def identity(path):
    lines = [line.strip() for line in Path(path).read_text(encoding="ascii").splitlines()]
    keys = [line for line in lines if line and not line.startswith("#")]
    if len(keys) != 1:
        raise ValueError("the key file must contain one age X25519 identity")
    text = keys[0]
    if not text.startswith("AGE-SECRET-KEY-1") or text != text.upper():
        raise ValueError("not an age X25519 identity")
    hrp, data = text.lower().rsplit("1", 1)
    values = [ALPHABET.index(char) for char in data]
    checksum = 1
    for value in [*(ord(c) >> 5 for c in hrp), 0, *(ord(c) & 31 for c in hrp), *values]:
        top = checksum >> 25
        checksum = (checksum & 0x1ffffff) << 5 ^ value
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                checksum ^= generator
    if checksum != 1 or len(values) != 58:
        raise ValueError("invalid age identity checksum or length")
    bits = 0
    count = 0
    decoded = bytearray()
    for value in values[:-6]:
        bits = (bits << 5) | value
        count += 5
        if count >= 8:
            count -= 8
            decoded.append((bits >> count) & 255)
    if len(decoded) != 32 or bits & ((1 << count) - 1):
        raise ValueError("invalid age identity padding")
    return X25519PrivateKey.from_private_bytes(bytes(decoded))


def parse_file(text):
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("invalid file ending")
    lines = iter(text[:-1].split("\n"))

    def field(prefix):
        line = next(lines)
        if not line.startswith(prefix):
            raise ValueError("invalid file field")
        return line[len(prefix):]

    if field("sauce: ") != "1":
        raise ValueError("unsupported format")
    name = field("name: ")
    if not re.fullmatch(NAME, name):
        raise ValueError("invalid name")
    commitment = decode64(field("commitment: "))
    facts = sealed(field("facts: "))
    value = sealed(field("value: "))
    if len(commitment) != 32 or field("keys:"):
        raise ValueError("invalid commitment or keys")
    entries = []
    fingerprints = set()
    line = next(lines, None)
    while line is not None:
        if not line.startswith("  - for: "):
            raise ValueError("invalid reader")
        host = line[len("  - for: "):]
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?", host):
            raise ValueError("invalid reader name")
        line = next(lines)
        if line.startswith("    pgp: "):
            # This program has no GPG key, so it binds the fingerprint and skips the wrap.
            public = line[len("    pgp: "):]
            if host != "admin" or not re.fullmatch(r"[0-9A-F]{40}", public):
                raise ValueError("invalid GPG reader")
            if public in fingerprints:
                raise ValueError("repeated GPG reader")
            fingerprints.add(public)
            if not 1 <= len(decode64(field("    wrap: "))) <= LARGEST_PGP_WRAP:
                raise ValueError("invalid GPG wrap")
            entries.append((host, public, []))
            line = next(lines, None)
            continue
        if not line.startswith("    age: "):
            raise ValueError("invalid reader key")
        public = line[len("    age: "):]
        if not re.fullmatch(r"age1[a-z0-9]+", public) or field("    wrap:"):
            raise ValueError("invalid reader key")
        stanzas = []
        for line in lines:
            if not line.startswith("      - "):
                break
            words = line[len("      - "):].split(" ")
            if len(words) < 2 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+/._-]*", words[0]):
                raise ValueError("invalid stanza")
            if any(not re.fullmatch(r"[A-Za-z0-9+/._-]+", word) for word in words[1:-1]):
                raise ValueError("invalid stanza arguments")
            body = decode64(words[-1])
            if not body:
                raise ValueError("empty stanza")
            stanzas.append((words[0], words[1:-1], body))
        else:
            line = None
        if not stanzas:
            raise ValueError("missing stanza")
        entries.append((host, public, stanzas))
    if not entries:
        raise ValueError("missing readers")
    return name, commitment, facts, value, entries


def derive(key, salt, label):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label).derive(key)


def unwrap(private, entries, commitment):
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    for _, _, stanzas in entries:
        for tag, args, body in stanzas:
            if tag != "X25519":
                continue
            try:
                if len(args) != 1 or len(body) != 32:
                    continue
                share = decode64(args[0])
                if len(share) != 32:
                    continue
                shared = private.exchange(X25519PublicKey.from_public_bytes(share))
                key = derive(shared, share + public, b"age-encryption.org/v1/X25519")
                file_key = ChaCha20Poly1305(key).decrypt(NONCE, body, None)
            except (InvalidTag, ValueError):
                continue
            if hmac.compare_digest(derive(file_key, None, b"secret-sauce/1/commitment"), commitment):
                return file_key
    raise ValueError("no matching file key and commitment")


def unpad(data):
    if len(data) not in STEPS:
        raise ValueError("invalid padded length")
    size = int.from_bytes(data[:4], "big")
    if size > len(data) - 4 or any(data[4 + size:]):
        raise ValueError("invalid padding")
    return data[4:4 + size]


def check_facts(data):
    text = data.decode("ascii")
    lines = text.splitlines(keepends=True)
    if len(lines) < 2 or any(not line.endswith("\n") for line in lines):
        raise ValueError("invalid facts")
    version = lines.pop(0).removeprefix("version: ").removesuffix("\n")
    if not re.fullmatch(r"0|[1-9][0-9]*", version) or int(version) > 4294967295:
        raise ValueError("invalid version")
    order = {"set": 0, "issued": 1, "expires": 2, "generator": 3, "formerly": 4, "revoke": 5}
    previous = -1
    for line in lines:
        key, value = line[:-1].split(": ", 1)
        index = order[key]
        if index < previous or (index == previous and key != "formerly") or (previous == -1 and key != "set"):
            raise ValueError("invalid facts order")
        if key in ("set", "issued", "expires"):
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
                raise ValueError("invalid date")
            if value.startswith("0000-"):
                datetime.date.fromisoformat("0400" + value[4:])
            else:
                datetime.date.fromisoformat(value)
        elif key == "generator" and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid generator")
        elif key == "formerly" and not re.fullmatch(NAME, value):
            raise ValueError("invalid former name")
        elif key == "revoke" and value != "true":
            raise ValueError("invalid revoke")
        previous = index
    return data


def main():
    parser = argparse.ArgumentParser(description="Open a .sauce.yaml file with an age X25519 identity.")
    parser.add_argument("file", metavar="SECRET.sauce.yaml")
    parser.add_argument("key")
    parser.add_argument("--name")
    parser.add_argument("--print", action="store_true", dest="print_value")
    args = parser.parse_args()
    with open(args.file, "rb") as file:
        data = file.read(LARGEST_FILE + 1)
    if len(data) > LARGEST_FILE:
        raise ValueError("file larger than 1 MiB")
    name, commitment, facts, value, entries = parse_file(data.decode("ascii"))
    if args.name is not None and args.name != name:
        raise ValueError("name does not match")
    key = unwrap(identity(args.key), entries, commitment)
    fields = [b"1", name.encode(), commitment]
    for host, public, _ in entries:
        fields.extend((host.encode(), public.encode()))
    aad = b"".join(len(field).to_bytes(8, "big") + field for field in fields)
    facts = unpad(ChaCha20Poly1305(derive(key, None, b"secret-sauce/1/facts")).decrypt(NONCE, facts, aad))
    value = unpad(ChaCha20Poly1305(derive(key, None, b"secret-sauce/1/value")).decrypt(NONCE, value, aad))
    facts = check_facts(facts)
    output = b"name: " + name.encode() + b"\n" + facts
    output += b"value: " + value + b"\n" if args.print_value else f"length: {len(value)}\n".encode()
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration, UnicodeError, binascii.Error, InvalidTag) as error:
        print(f"sauce-decrypt: {error or 'invalid file'}", file=sys.stderr)
        sys.exit(1)
