import json
import unittest

from cyber_core.errors import CoreError
from cyber_core.protocol.serial import decode_uart, decode_i2c, decode_spi, parse_csv
from cyber_core.automotive.canfd import analyze_canfd
from cyber_core.vulnerability.secrets import scan_secrets
from cyber_core.vulnerability.sca import check_dependencies
from cyber_core.vulnerability.nmap_xml import parse_nmap_xml
from cyber_core.research.nvd import parse_nvd


def uart_wave(data, baud=1000, step=0.0001):
    bit = 1 / baud
    levels = []  # (start_time, level)
    t = 0.01
    levels.append((0, 1))
    for byte in data:
        levels.append((t, 0)); t += bit
        for k in range(8):
            levels.append((t, (byte >> k) & 1)); t += bit
        levels.append((t, 1)); t += bit * 2
    end = t + 0.01
    rows, now, idx, cur = [], 0.0, 0, 1
    while now <= end:
        while idx < len(levels) and levels[idx][0] <= now:
            cur = levels[idx][1]; idx += 1
        rows.append((now, [cur])); now += step
    return rows


class SerialTests(unittest.TestCase):
    def test_uart(self):
        r = decode_uart(uart_wave(b'Hi!'), 1000)
        self.assertEqual(bytes.fromhex(r['bytes']), b'Hi!')
        self.assertEqual(r['framing_or_parity_errors'], 0)

    def test_i2c(self):
        def byte_bits(v, ack=0):
            return [(v >> k) & 1 for k in range(7, -1, -1)] + [ack]
        seq = [(1, 1), (0, 1)]  # start
        for b in byte_bits(0x50 << 1) + byte_bits(0xAB):
            seq += [(b, 0), (b, 1), (b, 0)]
        seq += [(0, 0), (0, 1), (1, 1)]  # stop
        rows = [(i, list(v)) for i, v in enumerate([(1, 1)] + seq)]
        tx = decode_i2c(rows)['transactions']
        self.assertEqual(tx[0]['address'], 0x50)
        self.assertFalse(tx[0]['read'])
        self.assertEqual(tx[0]['data'], 'ab')

    def test_spi_mode0(self):
        rows = [(0, [1, 0, 0, 0]), (1, [0, 0, 0, 0])]
        t = 2
        for v in (0xA5,):
            for k in range(7, -1, -1):
                b = (v >> k) & 1
                rows.append((t, [0, 0, b, 1 - b])); rows.append((t + 1, [0, 1, b, 1 - b])); t += 2
        rows += [(t, [0, 0, 0, 0]), (t + 1, [1, 0, 0, 0])]
        f = decode_spi(rows)['frames'][0]
        self.assertEqual((f['mosi'], f['miso']), ('a5', '5a'))

    def test_csv_validation(self):
        with self.assertRaises(CoreError):
            parse_csv('t,a\n0,2\n1,0\n', 1)
        self.assertEqual(len(parse_csv('t,a\n0,1\n1,0\n', 1)), 2)


class CanFdTests(unittest.TestCase):
    def test_ok_and_rejects(self):
        r = analyze_canfd('(1.000000) can0 123##1' + 'AA' * 12 + '\n(1.100000) can0 123##3' + 'BB' * 64 + '\n')
        s = r['streams'][0]
        self.assertEqual((r['frames'], s['brs'], s['esi'], s['max_len']), (2, 2, 1, 64))
        with self.assertRaises(CoreError):
            analyze_canfd('(1.000000) can0 123##1' + 'AA' * 9)
        with self.assertRaises(CoreError):
            analyze_canfd('(1.000000) can0 123#AA')


class VulnTests(unittest.TestCase):
    def test_secrets_redacted(self):
        key = 'AKIA' + 'ABCDEFGHIJKLMNOP'
        r = scan_secrets('x=1\nk = "%s"\npassword = "hunter2hunter2"\n' % key)
        rules = {f['rule'] for f in r['findings']}
        self.assertIn('aws_access_key_id', rules)
        self.assertNotIn('hunter2hunter2', json.dumps(r))
        self.assertNotIn(key, json.dumps(r))

    def test_sca(self):
        adv = [{'id': 'ADV-1', 'ecosystem': 'pypi', 'package': 'foo', 'fixed_in': '2.0.0'}]
        r = check_dependencies('requirements.txt', 'foo==1.9.0\nbar==3.0\n', adv)
        self.assertEqual(r['vulnerable'][0]['advisory'], 'ADV-1')
        self.assertEqual(check_dependencies('requirements.txt', 'foo==2.0.0\n', adv)['vulnerable'], [])
        r = check_dependencies('package.json', '{"dependencies":{"foo":"^1.0.0"}}', [{'id': 'N', 'ecosystem': 'npm', 'package': 'foo', 'fixed_in': '1.2'}])
        self.assertEqual(len(r['vulnerable']), 1)
        with self.assertRaises(CoreError):
            check_dependencies('requirements.txt', '', [{'id': 1}])

    def test_nmap(self):
        xml = '<nmaprun><host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.0"/></port><port protocol="tcp" portid="23"><state state="closed"/></port></ports></host></nmaprun>'
        r = parse_nmap_xml(xml)
        self.assertEqual(r['hosts'][0]['open_ports'][0]['port'], 22)
        self.assertEqual(len(r['hosts'][0]['open_ports']), 1)
        with self.assertRaises(CoreError):
            parse_nmap_xml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')
        with self.assertRaises(CoreError):
            parse_nmap_xml('<other/>')

    def test_nvd(self):
        doc = {'vulnerabilities': [{'cve': {'id': 'CVE-2024-1', 'published': '2024-01-01', 'descriptions': [{'lang': 'en', 'value': 'Bad'}],
               'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}]}}}]}
        r = parse_nvd(json.dumps(doc))['cves'][0]
        self.assertEqual((r['id'], r['cvss'], r['severity']), ('CVE-2024-1', 9.8, 'CRITICAL'))
        with self.assertRaises(CoreError):
            parse_nvd('{}')


if __name__ == '__main__':
    unittest.main()
