"""Bounded, offline firmware inspection; never executes or rewrites input."""
from hashlib import sha256
from pathlib import Path
import struct

from cyber_core.errors import CoreError

__all__ = ['analyze_firmware', 'compare_firmware']


def _fail(message):
    raise CoreError('Firmware: ' + message)


def _read(path, maximum):
    if type(maximum) is not int or maximum < 1:
        _fail('max_bytes must be a positive integer')
    try:
        with Path(path).open('rb') as source:
            data = source.read(maximum + 1)
    except (OSError, ValueError, TypeError, OverflowError):
        _fail('cannot read input file')
    if not data:
        _fail('empty input')
    if len(data) > maximum:
        _fail('input exceeds max_bytes')
    return data


def _records(data, maximum):
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        _fail('record file is not ASCII')
    count = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        count += 1
        if count > maximum:
            _fail('record count exceeds max_records')
        if line != line.strip() or len(line) > 1024:
            _fail('invalid record whitespace or length')
        yield line


def _hexbytes(text):
    if len(text) % 2 or any(c not in '0123456789abcdefABCDEF' for c in text):
        _fail('invalid hexadecimal record')
    return bytes.fromhex(text)


def _insert(memory, address, payload, max_decoded_bytes):
    if address < 0 or address + len(payload) > 0x100000000:
        _fail('address exceeds 32-bit range')
    if len(memory) + len(payload) > max_decoded_bytes:
        _fail('decoded data exceeds max_decoded_bytes')
    for offset, value in enumerate(payload):
        location = address + offset
        if location in memory:
            _fail('overlapping or duplicate data address')
        memory[location] = value


def _ihex(data, maximum, max_decoded_bytes):
    memory, base, ended, entry, count = {}, 0, False, None, 0
    for line in _records(data, maximum):
        if ended or not line.startswith(':'):
            _fail('record after EOF or invalid Intel HEX signature')
        record = _hexbytes(line[1:])
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) & 255:
            _fail('invalid Intel HEX length or checksum')
        count += 1
        address = int.from_bytes(record[1:3], 'big')
        kind, payload = record[3], record[4:-1]
        if kind == 0:
            if address + len(payload) > 65536:
                _fail('Intel HEX record crosses address window')
            _insert(memory, base + address, payload, max_decoded_bytes)
        elif kind == 1:
            if address or payload:
                _fail('invalid EOF record')
            ended = True
        elif kind in (2, 4):
            if address or len(payload) != 2:
                _fail('invalid extended address record')
            base = int.from_bytes(payload, 'big') << (4 if kind == 2 else 16)
        elif kind in (3, 5):
            if address or len(payload) != 4 or entry is not None:
                _fail('invalid or repeated start address record')
            entry = ((int.from_bytes(payload[:2], 'big') << 4) + int.from_bytes(payload[2:], 'big')) if kind == 3 else int.from_bytes(payload, 'big')
        else:
            _fail('unsupported Intel HEX record type')
    if not ended or not memory:
        _fail('missing EOF or no data records')
    return memory, {'records': count, 'entry_point': entry}


def _srecord(data, maximum, max_decoded_bytes):
    widths = {0: 2, 1: 2, 2: 3, 3: 4, 5: 2, 6: 3, 7: 4, 8: 3, 9: 2}
    memory, ended, data_kind, entry, count, data_count, declared = {}, False, None, None, 0, 0, False
    for line in _records(data, maximum):
        if ended or len(line) < 4 or line[0] != 'S' or line[1] not in '012356789':
            _fail('invalid S-record or record after termination')
        kind = int(line[1])
        record = _hexbytes(line[2:])
        width = widths[kind]
        if len(record) < width + 2 or len(record) != record[0] + 1 or sum(record) & 255 != 255:
            _fail('invalid S-record length or checksum')
        count += 1
        address = int.from_bytes(record[1:1 + width], 'big')
        payload = record[1 + width:-1]
        if kind in (1, 2, 3):
            if declared or (data_kind is not None and kind != data_kind):
                _fail('mixed data types or data after count record')
            data_kind = kind
            if address + len(payload) > 1 << (width * 8):
                _fail('S-record address overflow')
            _insert(memory, address, payload, max_decoded_bytes)
            data_count += 1
        elif kind in (5, 6):
            if payload or declared or address != data_count:
                _fail('invalid S-record count')
            declared = True
        elif kind in (7, 8, 9):
            if payload or data_kind is None or kind != 10 - data_kind:
                _fail('invalid S-record termination')
            ended, entry = True, address
        elif kind == 0:
            if count != 1 or address:
                _fail('misplaced S-record header')
    if not ended or not memory:
        _fail('missing termination or no data records')
    return memory, {'records': count, 'entry_point': entry, 'data_record_type': data_kind}


def _elf(data):
    if len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        _fail('invalid ELF identification')
    bits, endian = (32 if data[4] == 1 else 64), ('little' if data[5] == 1 else 'big')
    prefix = '<' if endian == 'little' else '>'
    size = 52 if bits == 32 else 64
    if len(data) < size:
        _fail('truncated ELF header')
    values = struct.unpack_from(prefix + ('HHIIIIIHHHHHH' if bits == 32 else 'HHIQQQIHHHHHH'), data, 16)
    typ, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = values
    if version != 1 or ehsize != size:
        _fail('invalid ELF header version or size')
    if phnum == 65535 or shstr == 65535 or (shoff and shnum == 0):
        _fail('ELF extended table numbering is unsupported')
    for offset, width, count, expected in ((phoff, phsize, phnum, 32 if bits == 32 else 56), (shoff, shsize, shnum, 40 if bits == 32 else 64)):
        if count and (offset < size or width != expected or offset + width * count > len(data)):
            _fail('ELF table outside input or invalid entry size')
    if shstr and shstr >= shnum:
        _fail('invalid ELF string table index')
    from cyber_core.firmware.structures import elf_details
    details = elf_details(data, bits=bits, endian=endian, machine=machine,
                          phoff=phoff, phnum=phnum, shoff=shoff, shnum=shnum, shstr=shstr)
    return {'class_bits': bits, 'endian': endian, 'machine': machine, 'type': typ, 'entry_point': entry, **details}


def _pe(data):
    if len(data) < 64:
        _fail('truncated DOS header')
    offset = int.from_bytes(data[60:64], 'little')
    if offset < 64 or offset + 24 > len(data) or data[offset:offset + 4] != b'PE\0\0':
        _fail('invalid PE signature or COFF header bounds')
    machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from('<HHIIIHH', data, offset + 4)
    optional = offset + 24
    end = optional + optional_size
    if optional_size < 2 or end + sections * 40 > len(data):
        _fail('truncated PE optional header or section table')
    magic = int.from_bytes(data[optional:optional + 2], 'little')
    required = {0x10b: 96, 0x20b: 112}.get(magic)
    if required is None or optional_size < required:
        _fail('invalid PE optional header')
    directories = int.from_bytes(data[optional + required - 4:optional + required], 'little')
    if required + directories * 8 > optional_size:
        _fail('PE directories exceed optional header')
    for i in range(sections):
        section = end + i * 40
        raw_size, raw_offset = struct.unpack_from('<II', data, section + 16)
        if raw_size and (raw_offset < end + sections * 40 or raw_offset + raw_size > len(data)):
            _fail('PE section outside input')
    from cyber_core.firmware.structures import pe_details
    details = pe_details(data, machine=machine, optional=optional, optional_size=optional_size,
                         sections=sections, magic=magic, characteristics=characteristics)
    return {'class_bits': 32 if magic == 0x10b else 64, 'endian': 'little', 'machine': machine, 'sections': sections, **details}


def _load(path, max_bytes, max_records, max_decoded_bytes):
    if type(max_records) is not int or max_records < 1:
        _fail('max_records must be a positive integer')
    if type(max_decoded_bytes) is not int or not 1 <= max_decoded_bytes <= 1048576:
        _fail('max_decoded_bytes must be an integer between 1 and 1048576')
    data = _read(path, max_bytes)
    signature = data.lstrip()[:2]
    memory = None
    if signature.startswith(b':'):
        fmt, (memory, metadata) = 'intel_hex', _ihex(data, max_records, max_decoded_bytes)
    elif len(signature) == 2 and signature[:1] == b'S' and signature[1:2].isdigit():
        fmt, (memory, metadata) = 'srecord', _srecord(data, max_records, max_decoded_bytes)
    elif data.startswith(b'\x7fELF'):
        fmt, metadata = 'elf', _elf(data)
    elif data.startswith(b'MZ'):
        fmt, metadata = 'pe', _pe(data)
    else:
        fmt, metadata = 'bin', {'validation_scope': 'opaque bytes; architecture and load address unknown'}
    result = {'format': fmt, 'size_bytes': len(data), 'sha256': sha256(data).hexdigest(), 'data_bytes': len(memory) if memory is not None else len(data), 'structure_validated': fmt != 'bin', 'metadata': metadata}
    if memory is not None:
        result.update(address_min=min(memory), address_max=max(memory), address_space='absolute')
    else:
        result['address_space'] = 'file_offset'
    return result, data if memory is None else memory


def analyze_firmware(path, *, max_bytes=67108864, max_records=100000, max_decoded_bytes=1048576):
    """Inspect bounded bytes. Header validation does not establish executable safety."""
    return _load(path, max_bytes, max_records, max_decoded_bytes)[0]


def compare_firmware(first, second, *, max_bytes=67108864, max_decoded_bytes=1048576):
    """Compare sparse absolute addresses or opaque file offsets, without gap filling."""
    a, left = _load(first, max_bytes, 100000, max_decoded_bytes)
    b, right = _load(second, max_bytes, 100000, max_decoded_bytes)
    if a['address_space'] != b['address_space']:
        _fail('cannot compare absolute addresses with file offsets')
    sparse = isinstance(left, dict)
    addresses = sorted(left.keys() | right.keys()) if sparse else range(max(len(left), len(right)))
    missing_left = missing_right = differing = 0
    ranges, previous = [], None
    range_count = 0
    for address in addresses:
        lv = left.get(address) if sparse else (left[address] if address < len(left) else None)
        rv = right.get(address) if sparse else (right[address] if address < len(right) else None)
        if lv == rv:
            continue
        differing += 1
        missing_left += lv is None
        missing_right += rv is None
        if previous is None or address != previous + 1:
            range_count += 1
            if len(ranges) < 1000:
                ranges.append({'start': address, 'end_exclusive': address + 1})
        elif range_count <= 1000:
            ranges[-1]['end_exclusive'] = address + 1
        previous = address
    return {'first': a, 'second': b, 'address_space': a['address_space'], 'differing_bytes': differing, 'missing_from_first': missing_left, 'missing_from_second': missing_right, 'changed_ranges': ranges, 'changed_ranges_total': range_count, 'ranges_truncated': range_count > 1000}
