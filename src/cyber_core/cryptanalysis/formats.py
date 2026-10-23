"""Allowlisted password validators. No commands, network, disk extraction or secret export."""
import importlib.util
import io
import lzma
import zlib
import zipfile

from cyber_core.errors import CoreError

MODES = ("ccaes1", "ssh-private", "zip", "7z", "pdf", "office", "pkcs12", "rar5")
MODULES = {"ccaes1": "cryptography", "ssh-private": "cryptography", "zip": "pyzipper",
           "7z": "py7zr", "pdf": "pypdf", "office": "msoffcrypto", "pkcs12": "cryptography", "rar5": "cryptography"}
VALIDATION = {"zip": "all encrypted members read; CRC or AES authentication checked",
              "7z": "encrypted payload decoded; all regular member CRCs checked",
              "pdf": "PDF Standard security password verifier",
              "office": "Office password verifier and decrypted OOXML ZIP integrity",
              "pkcs12": "PKCS12 password and contained key/certificate parsing",
              "rar5": "RAR5 password-check verifier; payload integrity not verified"}
MAX_EXPANDED = 16 * 1024 * 1024
MAX_MEMBERS = 256
SIGNATURES = {"ccaes1": (b"CCAES1",),
              "ssh-private": (b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
                              b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
                              b"-----BEGIN PRIVATE KEY-----"),
              "zip": (b"PK\x03\x04", b"PK\x05\x06"), "7z": (b"7z\xbc\xaf\x27\x1c",),
              "pdf": (b"%PDF-",), "office": (bytes.fromhex("d0cf11e0a1b11ae1"),),
              "pkcs12": (b"0",), "rar5": (b"Rar!\x1a\x07\x01\x00",)}

def inventory():
    result = {mode: {"available": importlib.util.find_spec(module) is not None,
                     "dependency": module, "operation": "password_validation" if mode in VALIDATION else mode}
              for mode, module in MODULES.items()}
    result["rar"] = {"available": False, "reason": "Use rar5 for RAR5; no validated RAR4 backend in this release"}
    return result

def select_mode(mode, header):
    if mode == "auto":
        # DER is ambiguous: PKCS12 must be selected explicitly.
        mode = next((name for name in MODES if name != "pkcs12" and header.startswith(SIGNATURES[name])), None)
    if mode not in MODES or not header.startswith(SIGNATURES[mode]):
        raise CoreError("Unsupported recovery format; select a supported mode for the actual file bytes")
    if not inventory()[mode]["available"]:
        raise CoreError("Recovery dependency unavailable; install the recovery extra in the authorized remote environment")
    return mode

def _members(items, size_of):
    if not items or len(items) > MAX_MEMBERS:
        raise ValueError("Archive member limit")
    sizes = [size_of(item) for item in items]
    if any(type(size) is not int or size < 0 for size in sizes) or sum(sizes) > MAX_EXPANDED:
        raise ValueError("Archive expanded byte limit")

class BoundedBuffer(io.BytesIO):
    def write(self, data):
        if self.tell() + len(data) > MAX_EXPANDED:
            raise ValueError("Expanded byte limit")
        return super().write(data)

def _zip(raw, candidate):
    import pyzipper
    with pyzipper.AESZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        _members(members, lambda item: item.file_size)
        protected = [item for item in members if item.flag_bits & 1 and not item.is_dir()]
        if not any(item.file_size for item in protected):
            return False
        archive.setpassword(candidate)
        total = 0
        try:
            for item in members:
                if item.is_dir():
                    continue
                with archive.open(item) as stream:
                    while chunk := stream.read(65536):
                        total += len(chunk)
                        if total > MAX_EXPANDED:
                            raise ValueError("Expanded byte limit")
        except (RuntimeError, pyzipper.BadZipFile, zlib.error, lzma.LZMAError, OSError, EOFError):
            return False
    return True

def _seven(raw, candidate):
    import py7zr
    from py7zr.exceptions import PasswordRequired, Bad7zFile, CrcError, DecompressionError
    try:
        # Passing a password sets needs_password even on a plain archive. Probe
        # without one first to avoid declaring an arbitrary password successful.
        try:
            with py7zr.SevenZipFile(io.BytesIO(raw)) as probe:
                protected = probe.needs_password()
        except PasswordRequired:
            protected = True
        if not protected:
            return False
        try:
            opened = py7zr.SevenZipFile(io.BytesIO(raw), password=candidate.decode("utf-8"),
                                       max_extract_size=MAX_EXPANDED)
        except (TypeError, ValueError, EOFError):
            # py7zr can report an incorrect encrypted-header password as
            # TypeError while parsing the unsuccessfully decrypted header.
            return False
        with opened as archive:
            members = archive.list()
            _members(members, lambda item: item.uncompressed)
            files = [item for item in members if item.is_file]
            if (not any(item.uncompressed for item in files) or
                any(not item.is_file and not item.is_directory for item in members) or
                any(item.crc32 is None for item in files) or
                len({item.filename for item in members}) != len(members)):
                raise ValueError("Unsupported archive member or missing integrity verifier")
            class Sink(py7zr.Py7zIO):
                def __init__(self, factory):
                    self.factory, self.count, self.crc = factory, 0, 0
                def write(self, data):
                    self.factory.total += len(data)
                    if self.factory.total > MAX_EXPANDED:
                        raise ValueError("Expanded byte limit")
                    self.count += len(data)
                    self.crc = zlib.crc32(data, self.crc)
                    return len(data)
                def read(self, size=None):
                    return b""
                def seek(self, offset, whence=0):
                    return self.count
                def flush(self):
                    pass
                def size(self):
                    return self.count
            class Factory(py7zr.WriterFactory):
                def __init__(self):
                    self.total, self.products = 0, {}
                def create(self, filename):
                    sink = Sink(self)
                    self.products[filename] = sink
                    return sink
            factory = Factory()
            archive.extractall(factory=factory)
            for item in files:
                sink = factory.products.get(item.filename)
                if sink is None or sink.count != item.uncompressed or sink.crc != item.crc32:
                    return False
    except (Bad7zFile, CrcError, DecompressionError, lzma.LZMAError):
        return False
    return True

def _pdf(raw, candidate):
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(raw), strict=True)
    if not reader.is_encrypted:
        return False
    return bool(reader.decrypt(candidate.decode("utf-8")))

def _office(raw, candidate):
    import msoffcrypto
    from msoffcrypto.exceptions import InvalidKeyError
    office = msoffcrypto.OfficeFile(io.BytesIO(raw))
    if not office.is_encrypted():
        return False
    # Legacy binary Office encryption has different verification contracts.
    if office.format != "ooxml" or office.type not in ("agile", "standard"):
        raise ValueError("Unsupported Office encryption")
    try:
        office.load_key(password=candidate.decode("utf-8"), verify_password=True)
    except InvalidKeyError:
        return False
    # A verifier match followed by corrupt payload is not a wrong password.
    # Leave the session at a retryable failure rather than exhausting the list.
    plain = BoundedBuffer()
    office.decrypt(plain, verify_integrity=office.type == "agile")
    plain.seek(0)
    with zipfile.ZipFile(plain) as archive:
        members = archive.infolist()
        _members(members, lambda item: item.file_size)
        if "[Content_Types].xml" not in archive.namelist():
            raise ValueError("Not an OOXML package")
        total = 0
        for member in members:
            if member.is_dir():
                continue
            with archive.open(member) as stream:
                while block := stream.read(65536):
                    total += len(block)
                    if total > MAX_EXPANDED:
                        raise ValueError("Expanded byte limit")
    return True

def _pkcs12(raw, candidate):
    from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
    try:
        load_key_and_certificates(raw, None)
    except ValueError:
        pass
    else:
        return False  # No password needed.
    try:
        key, certificate, extras = load_key_and_certificates(raw, candidate)
    except ValueError:
        return False
    return key is not None or certificate is not None or bool(extras)

def validate_password(mode, raw, candidate):
    from cyber_core.cryptanalysis.rar5 import verify_password as _rar5
    validators = {"rar5": _rar5, "zip": _zip, "7z": _seven, "pdf": _pdf, "office": _office, "pkcs12": _pkcs12}
    if mode not in validators:
        raise ValueError("Unsupported password validator")
    if not validators[mode](raw, candidate):
        return {"matched": False}
    result = {"matched": True, "password_validated": True, "format": mode, "validation": VALIDATION[mode]}
    if mode == "rar5":
        result["payload_integrity_verified"] = False
    return result
