"""Bounded recovery triage without supplied secrets. No decryption or extraction."""
import struct
from cyber_core.errors import CoreError

ZIP_SPEC = 'https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT'
CFB_SPEC = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea'

# IDs describe signature observations, not validated format implementations.
SIGNATURES = (
    (b'CCAES1', 'ccaes1', 'encrypted-envelope'),
    (b'PK\x03\x04', 'zip', 'archive'),
    (b'PK\x05\x06', 'zip', 'archive'),
    (b'PK\x07\x08', 'zip', 'archive'),
    (b'%PDF-', 'pdf', 'document'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole-cfb', 'compound-container'),
    (b'7z\xbc\xaf\x27\x1c', '7z', 'archive'),
    (b'Rar!\x1a\x07\x01\x00', 'rar5', 'archive'),
    (b'Rar!\x1a\x07\x00', 'rar4', 'archive'),
    (b'LUKS\xba\xbe', 'luks', 'encrypted-volume'),
    (b'Salted__', 'openssl-salted', 'encrypted-envelope'),
    (b'\x1f\x8b\x08', 'gzip', 'compressed-stream'),
    (b'SQLite format 3\x00', 'sqlite', 'database'),
    (b'\x7fELF', 'elf', 'executable-or-firmware'),
    (b'MZ', 'dos-pe', 'executable-or-firmware'),
    (b'\x89PNG\r\n\x1a\n', 'png', 'image'),
    (b'\xff\xd8\xff', 'jpeg', 'image'),
)


def _zip(data, report):
    report['sources'].append(ZIP_SPEC)
    report['limitations'].append('Other members may use different protection; the central directory and payload integrity were not validated.')
    if not data.startswith(b'PK\x03\x04'):
        report['next_steps'].append('Validate central directory, split volumes and local headers using a bounded ZIP parser.')
        return
    if len(data) < 30:
        report['metadata_status'] = 'truncated_or_outside_sample'
        return
    flag, method = struct.unpack_from('<HH', data, 6)
    name_len, extra_len = struct.unpack_from('<HH', data, 26)
    end = 30 + name_len + extra_len
    details = report['details']
    details.update({'coverage': 'first_local_header_only', 'first_member_encrypted_flag': bool(flag & 1),
                    'first_member_compression_method': method})
    if flag & 1:
        report['encryption_evidence'] = 'header_declares_encryption'
        report['observations'].append('First member declares the encrypted flag; cryptographic validity is not established.')
    report['metadata_status'] = 'first_local_header_parsed'
    if end > len(data):
        report['metadata_status'] = 'truncated_or_outside_sample'
        return
    offset = 30 + name_len
    while offset < end:
        if offset + 4 > end:
            report['metadata_status'] = 'malformed_extra_field'
            break
        field, size = struct.unpack_from('<HH', data, offset)
        offset += 4
        if offset + size > end:
            report['metadata_status'] = 'malformed_extra_field'
            break
        if field == 0x9901 and size >= 7:
            version, vendor, strength, underlying = struct.unpack_from('<H2sBH', data, offset)
            if vendor == b'AE' and version in (1, 2) and strength in (1, 2, 3):
                details['first_member_aes_strength_bits'] = {1: 128, 2: 192, 3: 256}[strength]
                details['first_member_underlying_compression_method'] = underlying
                report['observations'].append('First member has an AES extra-field declaration; payload authentication was not tested.')
        offset += size
    report['next_steps'].append('Validate every member and integrity metadata before selecting a ZIP recovery procedure; no archive members were extracted.')


def assess(path, *, entropy=None, max_sample=65536):
    if not 1 <= max_sample <= 262144:
        raise CoreError('Invalid assessment sample limit')
    with open(path, 'rb') as handle:
        data = handle.read(max_sample)
        more = bool(handle.read(1))
    report = {
        'engine': 'static-triage-v1', 'format_id': 'unknown', 'family': 'unclassified',
        'format_validated': False, 'metadata_status': 'signature_only',
        'encryption_evidence': 'not_established', 'recovery_demonstrated': False,
        'sample_bytes': len(data), 'sample_truncated': more, 'details': {}, 'sources': [],
        'observations': [],
        'next_steps': ['Inventory owner-authorized backups, version history, recovery exports and vendor documentation; no search outside the registered scope is performed.'],
        'limitations': ['This is recovery feasibility triage, not recovered data.',
                        'Only a bounded prefix was inspected; signature recognition does not validate a complete format.',
                        'High entropy alone does not establish encryption. Missing markers do not establish plaintext.'],
        'routes': [{'route': 'authorized_backup_or_version_restore', 'status': 'requires_inventory_and_validation'},
                   {'route': 'format_specific_repair', 'status': 'requires_format_validation_and_implementation'},
                   {'route': 'cryptographic_decryption', 'status': 'not_attempted_no_material_supplied'}],
    }
    if entropy is not None:
        report['details']['whole_file_entropy'] = entropy
    for magic, identifier, family in SIGNATURES:
        if data.startswith(magic):
            report.update(format_id=identifier, family=family)
            report['observations'].append('Recognized a ' + identifier + ' signature at byte zero.')
            break
    identifier = report['format_id']
    if identifier == 'zip':
        _zip(data, report)
    elif identifier == 'pdf':
        if b'/Encrypt' in data:
            report['encryption_evidence'] = 'marker_only'
            report['observations'].append('An /Encrypt byte marker occurs in the prefix; it may be ordinary stream data.')
        report['next_steps'].append('Validate cross-reference/trailer structures and the encryption dictionary with a PDF parser before assessing restrictions or damage.')
    elif identifier == 'ole-cfb':
        report['sources'].append(CFB_SPEC)
        if any(marker.encode('utf-16le') in data for marker in ('EncryptedPackage', 'EncryptionInfo')):
            report['encryption_evidence'] = 'marker_only'
            report['observations'].append('Possible Office encryption stream-name marker; directory structures have not been parsed.')
        report['next_steps'].append('Validate CFB directory and stream metadata; do not infer that all OLE files are encrypted Office documents.')
    elif identifier == 'ccaes1':
        report['encryption_evidence'] = 'header_declares_encryption'
        if len(data) < 34:
            report['metadata_status'] = 'truncated_or_outside_sample'
        report['next_steps'].append('This synthetic envelope declares AES-256-GCM; no plaintext recovery is demonstrated without the matching material. Investigate authorized backup and key-management records if available.')
    elif identifier == 'luks':
        report['sources'].append('https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md')
        report['encryption_evidence'] = 'header_declares_encryption'
        if len(data) >= 8:
            report['details']['declared_version'] = int.from_bytes(data[6:8], 'big')
        report['next_steps'].append('Assess authorized header backups, keyslot health and recovery records using a validated LUKS parser; never modify the original volume.')
    elif identifier == 'openssl-salted':
        report['sources'].append('https://github.com/openssl/openssl/blob/master/apps/enc.c')
        report['encryption_evidence'] = 'header_declares_encryption'
        report['limitations'].append('The Salted__ signature does not identify a cipher, key size, KDF or application version.')
        report['next_steps'].append('Identify the creating application, cipher/KDF parameters and authorized backup/recovery sources before evaluating recovery.')
    elif identifier in ('7z', 'rar4', 'rar5'):
        report['sources'].append('https://www.7-zip.org/recover.html' if identifier == '7z' else 'https://www.rarlab.com/technote.htm')
        report['next_steps'].append('Use a validated archive parser to distinguish corruption, missing volumes, compression and encryption; archive signature alone does not establish password protection.')
    elif identifier == 'unknown':
        report['next_steps'].append('Collect provenance, creating software/version and reference samples; assess proprietary structure without assuming cryptography.')
    else:
        report['next_steps'].append('Validate structure and integrity with a format-specific parser; assess corruption and available backups before proposing repair.')
    return report
