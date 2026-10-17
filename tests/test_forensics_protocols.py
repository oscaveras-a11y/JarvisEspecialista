"""Synthetic contracts for bounded offline disk/packet inventory."""
import hashlib
import json
import struct
import unittest
import zlib

from cyber_core.forensics.disk import inspect_disk_image
from cyber_core.protocols_pcap import inspect_pcap


def mbr(entries=((0x83, 2, 3),), sectors=100, sector_size=512):
    image = bytearray(sectors * sector_size)
    image[510:512] = b"\x55\xaa"
    for i, (kind, first, count) in enumerate(entries):
        entry = 446 + i * 16
        image[entry + 4] = kind
        struct.pack_into("<II", image, entry + 8, first, count)
    return image


def gpt(overlap=False, sector_size=512):
    image = mbr(((0xEE, 1, 99),), sector_size=sector_size)
    entries = bytearray(128 * 128)
    entries[:16] = b"\x01" * 16
    entries[16:32] = b"\x02" * 16
    struct.pack_into("<QQ", entries, 32, 34, 39)
    if overlap:
        entries[128:144] = b"\x03" * 16
        entries[144:160] = b"\x04" * 16
        struct.pack_into("<QQ", entries, 160, 38, 42)
    image[2 * sector_size:2 * sector_size + len(entries)] = entries
    first_usable = max(34, 2 + (len(entries) + sector_size - 1) // sector_size)
    header = bytearray(92)
    struct.pack_into("<8sIIIIQQQQ16sQIII", header, 0,
                     b"EFI PART", 0x10000, 92, 0, 0, 1, 99,
                     first_usable, 66, b"\x05" * 16, 2, 128, 128,
                     zlib.crc32(entries))
    struct.pack_into("<I", header, 16, zlib.crc32(header))
    image[sector_size:sector_size + 92] = header
    return image


def rehash_header(image, sector_size=512):
    size = struct.unpack_from("<I", image, sector_size + 12)[0]
    struct.pack_into("<I", image, sector_size + 16, 0)
    struct.pack_into("<I", image, sector_size + 16,
                     zlib.crc32(image[sector_size:sector_size + size]))


def frame(protocol=17, fragment=0, payload=b"PRIVATE_TOKEN_PAYLOAD", tcp=False):
    transport = (struct.pack("!HHIIHHHH", 1234, 443, 1, 0, 0x5010, 4096, 0, 0)
                 if tcp else struct.pack("!HHHH", 1234, 53, 8 + len(payload), 0))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport) + len(payload),
                     7, fragment, 64, protocol, 0,
                     b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02")
    return b"\x01" * 6 + b"\x02" * 6 + b"\x08\x00" + ip + transport + payload


def pcap(packet=None, endian="<", nano=False, fraction=123, orig=None, snap=65535):
    packet = frame() if packet is None else packet
    magic = (b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    return (magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, snap, 1)
            + struct.pack(endian + "IIII", 1_700_000_000, fraction,
                          len(packet), len(packet) if orig is None else orig) + packet)


class DiskInventoryTests(unittest.TestCase):
    def test_mbr_offsets_hash_and_read_only(self):
        raw = bytes(mbr())
        result = inspect_disk_image(raw)
        self.assertEqual(result["format"], "mbr")
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["partitions"][0]["offset"], 1024)
        self.assertEqual(result["partitions"][0]["length"], 1536)
        self.assertEqual(result["overlaps"], [])
        self.assertEqual(raw, bytes(mbr()))

    def test_mbr_overlap_is_explicit(self):
        result = inspect_disk_image(bytes(mbr(((0x83, 2, 5), (0x83, 4, 5)))))
        self.assertEqual(result["overlaps"][0]["offset"], 2048)
        self.assertEqual(result["overlaps"][0]["length"], 1536)
        self.assertFalse(result["partition_ranges_disjoint"])

    def test_mbr_metadata_overlap_reported(self):
        result = inspect_disk_image(bytes(mbr(((0x83, 0, 3),))))
        self.assertTrue(any(x["right"] == "mbr" for x in result["overlaps"]))

    def test_mbr_out_of_bounds_rejected(self):
        with self.assertRaisesRegex(ValueError, "bounds"):
            inspect_disk_image(bytes(mbr(((0x83, 99, 2),))))

    def test_gpt_crc_offsets_and_backup_limitation(self):
        result = inspect_disk_image(bytes(gpt()))
        self.assertEqual(result["format"], "gpt_primary")
        self.assertEqual(result["partitions"][0]["offset"], 34 * 512)
        self.assertTrue(result["gpt"]["header_crc32_valid"])
        self.assertTrue(result["gpt"]["entries_crc32_valid"])
        self.assertFalse(result["gpt"]["backup_validated"])

    def test_gpt_4096_sector_offsets(self):
        result = inspect_disk_image(bytes(gpt(sector_size=4096)), sector_size=4096)
        self.assertEqual(result["partitions"][0]["offset"], 34 * 4096)

    def test_gpt_header_crc_failure_rejected(self):
        image = gpt()
        image[512 + 56] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            inspect_disk_image(bytes(image))

    def test_gpt_array_crc_failure_rejected(self):
        image = gpt()
        image[1024 + 60] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            inspect_disk_image(bytes(image))

    def test_gpt_array_bounds_precede_read(self):
        image = gpt()
        struct.pack_into("<Q", image, 512 + 72, 99)
        rehash_header(image)
        with self.assertRaisesRegex(ValueError, "bounds"):
            inspect_disk_image(bytes(image))

    def test_gpt_invalid_entry_size(self):
        image = gpt()
        struct.pack_into("<I", image, 512 + 84, 136)
        rehash_header(image)
        with self.assertRaisesRegex(ValueError, "entry size"):
            inspect_disk_image(bytes(image))

    def test_gpt_entry_count_budget(self):
        with self.assertRaisesRegex(ValueError, "partition limit"):
            inspect_disk_image(bytes(gpt()), max_partitions=32)

    def test_gpt_partition_overlap(self):
        result = inspect_disk_image(bytes(gpt(overlap=True)))
        self.assertEqual(result["overlaps"][0]["length"], 2 * 512)

    def test_image_limits_signatures_and_partial_sector(self):
        for raw in (b"", bytes(512), bytes(mbr())[:-1]):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                inspect_disk_image(raw)
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            inspect_disk_image(bytes(mbr()), max_bytes=512)

    def test_extended_partition_is_not_recursively_inferred(self):
        result = inspect_disk_image(bytes(mbr(((0x0F, 2, 3),))))
        self.assertEqual(result["partitions"][0]["kind"], "extended_container_unexpanded")


class PcapInventoryTests(unittest.TestCase):
    def test_all_byte_orders_and_timestamp_precisions(self):
        for order in ("<", ">"):
            for nano in (False, True):
                with self.subTest(order=order, nano=nano):
                    result = inspect_pcap(pcap(endian=order, nano=nano, fraction=123456))
                    self.assertEqual(result["byte_order"], "little" if order == "<" else "big")
                    self.assertEqual(result["timestamp_precision"], "nanosecond" if nano else "microsecond")
                    record = result["packets"][0]
                    self.assertEqual(record["record_offset"], 24)
                    self.assertEqual(record["data_offset"], 40)
                    self.assertEqual(record["timestamp_fraction"], 123456)
                    self.assertEqual(record["timestamp_ns"],
                                     1_700_000_000 * 10**9 + 123456 * (1 if nano else 1000))
                    self.assertEqual(record["ipv4"]["source"], "192.0.2.1")
                    self.assertEqual(record["transport"]["source_port"], 1234)

    def test_no_payload_export(self):
        result = inspect_pcap(pcap())
        self.assertNotIn("PRIVATE_TOKEN", json.dumps(result))
        self.assertNotIn("payload", result["packets"][0])

    def test_tcp_metadata(self):
        result = inspect_pcap(pcap(frame(protocol=6, tcp=True)))
        self.assertEqual(result["packets"][0]["transport"]["protocol"], "tcp")
        self.assertEqual(result["packets"][0]["transport"]["header_length"], 20)

    def test_ipv4_fragments_never_report_complete_transport(self):
        for flags_offset in (0x2000, 1, 0x2001):
            with self.subTest(fragment=flags_offset):
                result = inspect_pcap(pcap(frame(protocol=6, fragment=flags_offset, tcp=True)))
                packet = result["packets"][0]
                self.assertTrue(packet["ipv4"]["fragmented"])
                self.assertNotIn("transport", packet)
                self.assertIn("ipv4_fragment_transport_not_decoded", packet["issues"])

    def test_snaplen_capture_truncation(self):
        packet = frame()
        result = inspect_pcap(pcap(packet[:-5], orig=len(packet), snap=len(packet)))
        self.assertTrue(result["packets"][0]["capture_truncated"])
        self.assertIn("ipv4_packet_truncated", result["packets"][0]["issues"])
        self.assertNotIn("transport", result["packets"][0])

    def test_incomplete_record_and_record_header(self):
        result = inspect_pcap(pcap()[:-5])
        self.assertTrue(result["file_truncated"])
        self.assertTrue(result["packets"][0]["record_truncated"])
        self.assertNotIn("ipv4", result["packets"][0])
        result = inspect_pcap(pcap()[:30])
        self.assertTrue(result["file_truncated"])
        self.assertEqual(result["packets"], [])

    def test_timestamp_fraction_bounds(self):
        for nano, bad in ((False, 1_000_000), (True, 1_000_000_000)):
            with self.subTest(nano=nano), self.assertRaisesRegex(ValueError, "timestamp"):
                inspect_pcap(pcap(nano=nano, fraction=bad))

    def test_pcapng_explicitly_unsupported(self):
        with self.assertRaisesRegex(ValueError, "PCAPNG"):
            inspect_pcap(b"\x0a\x0d\x0d\x0a" + bytes(24))

    def test_lengths_validated(self):
        raw = bytearray(pcap())
        for offset, value in ((32, 65536), (36, 1)):
            broken = raw.copy()
            struct.pack_into("<I", broken, offset, value)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "length"):
                inspect_pcap(bytes(broken))

    def test_tcp_data_offset_bounds(self):
        packet = bytearray(frame(protocol=6, tcp=True))
        packet[14 + 20 + 12] = 0xF0
        result = inspect_pcap(pcap(bytes(packet)))
        self.assertIn("invalid_tcp_header_length", result["packets"][0]["issues"])
        self.assertNotIn("transport", result["packets"][0])

    def test_udp_length_bounds(self):
        packet = bytearray(frame())
        struct.pack_into("!H", packet, 14 + 20 + 4, 65535)
        result = inspect_pcap(pcap(bytes(packet)))
        self.assertIn("invalid_udp_length", result["packets"][0]["issues"])
        self.assertNotIn("transport", result["packets"][0])

    def test_ethernet_and_ipv4_bounds(self):
        for packet, issue in ((bytes(10), "ethernet_header_truncated"),
                              (frame()[:25], "ipv4_header_truncated")):
            with self.subTest(issue=issue):
                result = inspect_pcap(pcap(packet))
                self.assertIn(issue, result["packets"][0]["issues"])

    def test_non_ipv4_is_metadata_only(self):
        packet = bytearray(frame())
        packet[12:14] = b"\x86\xdd"
        result = inspect_pcap(pcap(bytes(packet)))
        self.assertNotIn("ipv4", result["packets"][0])

    def test_file_packet_and_linktype_limits(self):
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            inspect_pcap(pcap(), max_bytes=24)
        raw = pcap()
        result = inspect_pcap(raw + raw[24:], max_packets=1)
        self.assertTrue(result["packet_limit_reached"])
        self.assertEqual(result["next_record_offset"], len(raw))
        raw = bytearray(raw)
        struct.pack_into("<I", raw, 20, 101)
        with self.assertRaisesRegex(ValueError, "linktype"):
            inspect_pcap(bytes(raw))


if __name__ == "__main__":
    unittest.main()
