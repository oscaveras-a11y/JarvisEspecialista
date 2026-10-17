"""Bounded classic-PCAP metadata inventory; no sockets or payload export."""
from __future__ import annotations

import hashlib
import ipaddress
import struct

DEFAULT_MAX_BYTES = 16 * 1024 * 1024
HARD_MAX_BYTES = 64 * 1024 * 1024
HARD_MAX_PACKETS = 4096
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond", 1_000_000_000),
}


def _packet_metadata(frame: memoryview, data_offset: int) -> dict:
    result = {"issues": []}
    issues = result["issues"]
    if len(frame) < 14:
        issues.append("ethernet_header_truncated")
        return result
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    result["ethernet"] = {
        "offset": data_offset, "header_length": 14, "ethertype": ether_type,
        "destination": ":".join(f"{b:02x}" for b in frame[:6]),
        "source": ":".join(f"{b:02x}" for b in frame[6:12]),
    }
    if ether_type != 0x0800:
        issues.append("ethertype_not_decoded")
        return result
    if len(frame) < 34:
        issues.append("ipv4_header_truncated")
        return result
    ip = frame[14:]
    version, ihl = ip[0] >> 4, (ip[0] & 15) * 4
    if version != 4 or ihl < 20:
        issues.append("invalid_ipv4_header")
        return result
    if len(ip) < ihl:
        issues.append("ipv4_header_truncated")
        return result
    total_length, identification, flags_offset = struct.unpack_from("!HHH", ip, 2)
    if total_length < ihl:
        issues.append("invalid_ipv4_total_length")
        return result
    fragment_offset = (flags_offset & 0x1FFF) * 8
    more_fragments = bool(flags_offset & 0x2000)
    fragmented = more_fragments or fragment_offset != 0
    result["ipv4"] = {
        "offset": data_offset + 14, "header_length": ihl,
        "total_length": total_length, "protocol_number": ip[9],
        "identification": identification, "ttl": ip[8],
        "source": str(ipaddress.IPv4Address(bytes(ip[12:16]))),
        "destination": str(ipaddress.IPv4Address(bytes(ip[16:20]))),
        "fragment_offset_bytes": fragment_offset,
        "more_fragments": more_fragments, "fragmented": fragmented,
        "checksum_validated": False,
    }
    if total_length > len(ip):
        issues.append("ipv4_packet_truncated")
    if fragmented:
        issues.append("ipv4_fragment_transport_not_decoded")
        return result
    if total_length > len(ip):
        return result
    transport = ip[ihl:total_length]
    offset = data_offset + 14 + ihl
    if ip[9] == 6:
        if len(transport) < 20:
            issues.append("tcp_header_truncated")
            return result
        header_length = (transport[12] >> 4) * 4
        if not 20 <= header_length <= len(transport):
            issues.append("invalid_tcp_header_length")
            return result
        source, destination = struct.unpack_from("!HH", transport)
        result["transport"] = {
            "protocol": "tcp", "offset": offset, "header_length": header_length,
            "source_port": source, "destination_port": destination,
            "flags": ((transport[12] & 1) << 8) | transport[13],
            "checksum_validated": False,
        }
    elif ip[9] == 17:
        if len(transport) < 8:
            issues.append("udp_header_truncated")
            return result
        source, destination, length = struct.unpack_from("!HHH", transport)
        if length < 8 or length != len(transport):
            issues.append("invalid_udp_length")
            return result
        result["transport"] = {
            "protocol": "udp", "offset": offset, "header_length": 8,
            "datagram_length": length, "source_port": source,
            "destination_port": destination, "checksum_validated": False,
        }
    else:
        issues.append("ipv4_protocol_not_decoded")
    return result


def inspect_pcap(
    data: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES, max_packets: int = 256,
) -> dict:
    """Read classic PCAP 2.4 Ethernet/IPv4/TCP/UDP metadata from immutable bytes.

    Truncated record/header tails are reported; inconsistent declared lengths or
    timestamps raise ValueError. Integer nanoseconds preserve timestamp precision.
    No stream/fragment reassembly, PCAPNG, IPv6, VLAN, FCS, or checksum validation.
    The caller is responsible for authorization and verified-copy custody.
    """
    if type(max_bytes) is not int or not 24 <= max_bytes <= HARD_MAX_BYTES:
        raise ValueError("max_bytes must be an integer between 24 and 67108864")
    if type(max_packets) is not int or not 1 <= max_packets <= HARD_MAX_PACKETS:
        raise ValueError("packet limit must be an integer between 1 and 4096")
    if not isinstance(data, bytes):
        raise ValueError("data must be immutable bytes from a verified copy")
    if len(data) > max_bytes:
        raise ValueError("capture exceeds max_bytes")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raise ValueError("PCAPNG is explicitly unsupported")
    if len(data) < 24:
        raise ValueError("classic PCAP file header truncated")
    if data[:4] not in _MAGICS:
        raise ValueError("unsupported classic PCAP magic")
    endian, precision, divisor = _MAGICS[data[:4]]
    major, minor, reserved1, reserved2, snaplen, network = struct.unpack_from(
        endian + "HHIIII", data, 4)
    if (major, minor) != (2, 4):
        raise ValueError("only classic PCAP version 2.4 is supported")
    # Restrict to plain Ethernet without extra FCS metadata until a real FCS
    # implementation is present. Do not silently ignore the upper flag bits.
    if network != 1:
        raise ValueError("unsupported linktype or additional linktype flags")
    if snaplen == 0:
        raise ValueError("invalid snapshot length")
    result = {
        "schema_version": 1, "format": "pcap_classic", "version": "2.4",
        "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "byte_order": "little" if endian == "<" else "big",
        "timestamp_precision": precision, "timestamp_origin": "unix_utc",
        "snapshot_length": snaplen, "linktype": 1, "linktype_name": "ethernet",
        "packets": [], "file_truncated": False, "packet_limit_reached": False,
        "issues": [], "limitations": [
            "metadata_only", "no_payload_export", "no_network_io",
            "no_stream_or_fragment_reassembly", "no_checksum_validation",
            "no_pcapng_ipv6_vlan_or_fcs", "timestamps_are_capture_claims"],
    }
    pos, size = 24, len(data)
    while pos < size and len(result["packets"]) < max_packets:
        if size - pos < 16:
            result["file_truncated"] = True
            result["issues"].append({"code": "record_header_truncated", "offset": pos})
            break
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, pos)
        if fraction >= divisor:
            raise ValueError(f"invalid timestamp fraction at record offset {pos}")
        if captured > snaplen or captured > original:
            raise ValueError(f"invalid captured/original length at record offset {pos}")
        start = pos + 16
        available = min(captured, size - start)
        truncated = available != captured
        record = {
            "index": len(result["packets"]) + 1, "record_offset": pos,
            "data_offset": start, "timestamp_seconds": seconds,
            "timestamp_fraction": fraction,
            "timestamp_ns": seconds * 1_000_000_000 + fraction * (1_000_000_000 // divisor),
            "captured_length": captured, "original_length": original,
            "available_length": available, "capture_truncated": captured < original,
            "record_truncated": truncated,
        }
        if truncated:
            record["issues"] = ["record_data_truncated"]
            result["file_truncated"] = True
            result["packets"].append(record)
            break
        record.update(_packet_metadata(memoryview(data)[start:start + captured], start))
        result["packets"].append(record)
        pos = start + captured
    result["packet_limit_reached"] = (
        len(result["packets"]) == max_packets and pos < size and not result["file_truncated"])
    result["next_record_offset"] = pos
    result["packet_count_inspected"] = len(result["packets"])
    return result
