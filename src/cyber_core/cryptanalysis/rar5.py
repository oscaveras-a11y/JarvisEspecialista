"""Bounded RAR5 password-check parser. Does not decrypt or validate payload."""
import hashlib
import hmac
import struct
import zlib
from cyber_core.errors import CoreError

MAGIC = b"Rar!\x1a\x07\x01\x00"
MAX_INPUT = 8 * 1024 * 1024
MAX_BLOCKS = 1024
MAX_MEMBERS = 256
MAX_EXPANDED = 16 * 1024 * 1024
MAX_KDF_LOG2 = 20
MAX_KDF_TOTAL = 1 << 22

class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0
    def take(self, size):
        if type(size) is not int or size < 0 or size > len(self.data)-self.pos:
            raise CoreError("Truncated RAR5 metadata")
        result = self.data[self.pos:self.pos+size]
        self.pos += size
        return result
    def number(self, maximum_bytes=10):
        number = 0
        for index in range(maximum_bytes):
            value = self.take(1)[0]
            if index == 9 and value > 1:
                raise CoreError("RAR5 integer overflow")
            number |= (value & 127) << (7 * index)
            if not value & 128:
                return number
        raise CoreError("RAR5 integer limit")

def _crypt(data, *, headers, iv=None):
    stream = Reader(data)
    version, flags = stream.number(), stream.number()
    if version != 0 or flags & ~(1 if headers else 3) or not flags & 1:
        raise CoreError("Unsupported RAR5 encryption or missing password check")
    kdf = stream.take(1)[0]
    if not 0 <= kdf <= MAX_KDF_LOG2:
        raise CoreError("RAR5 KDF work limit")
    salt = stream.take(16)
    iv = iv if headers else stream.take(16)
    check, checksum = stream.take(8), stream.take(4)
    if stream.pos != len(data) or hashlib.sha256(check).digest()[:4] != checksum:
        raise CoreError("RAR5 password-check integrity failed")
    return (salt, kdf, iv, check)

def password_records(raw):
    """Return only verifier parameters. Never return file names or payload bytes."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INPUT or not raw.startswith(MAGIC):
        raise CoreError("Unsupported RAR5 container")
    stream = Reader(raw)
    stream.take(len(MAGIC))
    records, members, expanded, seen_main = [], 0, 0, False
    for _ in range(MAX_BLOCKS):
        expected_crc = struct.unpack("<I", stream.take(4))[0]
        start = stream.pos
        size = stream.number(3)
        end = stream.pos + size
        if size > 2*1024*1024 or end > len(raw):
            raise CoreError("RAR5 header size limit")
        if zlib.crc32(raw[start:end]) != expected_crc:
            raise CoreError("RAR5 header CRC failed")
        header = Reader(stream.take(size))
        kind, flags = header.number(), header.number()
        if flags & ~127 or flags & 24:
            raise CoreError("Unsupported RAR5 block or split volume")
        extra_size = header.number() if flags & 1 else 0
        data_size = header.number() if flags & 2 else 0
        body_end = len(header.data) - extra_size
        if body_end < header.pos or data_size > len(raw)-stream.pos:
            raise CoreError("RAR5 block range failed")
        body = Reader(header.data[header.pos:body_end])
        extra = Reader(header.data[body_end:])
        if kind == 4:
            if seen_main or records or extra_size or data_size:
                raise CoreError("Unexpected RAR5 encryption header")
            iv = stream.take(16)
            # A real encrypted header needs at least one AES block after its IV.
            if len(raw)-stream.pos < 16 or (len(raw)-stream.pos) % 16:
                raise CoreError("Truncated RAR5 encrypted header")
            records.append(_crypt(body.data, headers=True, iv=iv))
            return _bounded(records)
        if kind == 1:
            if seen_main:
                raise CoreError("Duplicate RAR5 main header")
            seen_main = True
            archive_flags = body.number()
            if archive_flags & 3 or archive_flags & ~31:
                raise CoreError("RAR5 multipart archives unsupported")
        elif kind in (2, 3):
            if not seen_main:
                raise CoreError("RAR5 file before main header")
            file_flags, unpacked, _attributes = body.number(), body.number(), body.number()
            if file_flags & ~15 or file_flags & 8:
                raise CoreError("Unknown RAR5 file size or flags")
            if file_flags & 2:
                body.take(4)
            if file_flags & 4:
                body.take(4)
            _compression, _host = body.number(), body.number()
            body.take(body.number())
            if body.pos != len(body.data):
                raise CoreError("Unexpected RAR5 file header fields")
            if kind == 2:
                members += 1
                expanded += unpacked
                if members > MAX_MEMBERS or expanded > MAX_EXPANDED:
                    raise CoreError("RAR5 declared member limit")
            while extra.pos < len(extra.data):
                record = Reader(extra.take(extra.number()))
                record_type = record.number()
                if record_type == 1:
                    if file_flags & 1 or kind != 2 or not data_size:
                        raise CoreError("Unsupported RAR5 encrypted service or directory")
                    records.append(_crypt(record.take(len(record.data)-record.pos), headers=False))
                elif record_type == 5:
                    raise CoreError("RAR5 redirection records unsupported")
        elif kind == 5:
            if not seen_main or data_size or extra_size or body.number() != 0 or body.pos != len(body.data):
                raise CoreError("Invalid RAR5 end marker")
            if stream.pos != len(raw):
                raise CoreError("Trailing RAR5 data unsupported")
            if not records:
                raise CoreError("RAR5 contains no supported password check")
            return _bounded(records)
        else:
            raise CoreError("Unknown RAR5 block type")
        stream.take(data_size)
    raise CoreError("RAR5 block count limit")

def _bounded(records):
    if not records or len(records) > MAX_MEMBERS or sum((1 << r[1])+32 for r in records) > MAX_KDF_TOTAL:
        raise CoreError("RAR5 aggregate verifier limit")
    return records

def verify_records(records, candidate):
    if not isinstance(candidate, bytes) or not 1 <= len(candidate) <= 1024 or any(c in candidate for c in (b"\0", b"\r", b"\n")):
        raise CoreError("Unsupported RAR5 candidate")
    try:
        if len(candidate.decode("utf-8")) > 127:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise CoreError("RAR5 candidate must be bounded UTF-8") from None
    matched = True
    for salt, kdf, _iv, expected in _bounded(records):
        value = hashlib.pbkdf2_hmac("sha256", candidate, salt, (1 << kdf)+32, 32)
        check = bytes(value[i] ^ value[i+8] ^ value[i+16] ^ value[i+24] for i in range(8))
        matched = hmac.compare_digest(check, expected) and matched
    return matched

def verify_password(raw, candidate):
    return verify_records(password_records(raw), candidate)

def converter_hashes(converted, records):
    """Require each converter line to describe an independently parsed verifier."""
    import re
    pattern = rb"\$rar5\$16\$([0-9a-f]{32})\$(\d{1,2})\$([0-9a-f]{32})\$8\$([0-9a-f]{16})"
    found = []
    for line in converted.splitlines():
        match = re.fullmatch(rb"[^:\r\n]{1,256}:(" + pattern + rb")", line)
        if not match:
            raise CoreError("Unsupported RAR5 converter output")
        # group1 is full hash; group2 salt, group3 KDF, group4 IV, group5 check.
        record = (bytes.fromhex(match[2].decode()), int(match[3]), bytes.fromhex(match[4].decode()),
                  bytes.fromhex(match[5].decode()))
        found.append((record, match[1]))
    if not found or len(found) > MAX_MEMBERS or set(r for r,h in found) != set(records):
        raise CoreError("RAR5 converter differs from verified input")
    return sorted(set(h for r,h in found))

def pot_matches(output, hashes):
    # John canonicalizes the unused IV to zeros in its potfile. Match only
    # hash prefixes, never parse or publish the secret following the colon.
    expected = []
    for value in hashes:
        fields = value.split(b"$")
        fields[5] = b"0" * 32
        expected.append(b"$".join(fields) + b":")
    lines = output.splitlines()
    return bool(expected) and all(any(line.startswith(prefix) for line in lines) for prefix in expected)
