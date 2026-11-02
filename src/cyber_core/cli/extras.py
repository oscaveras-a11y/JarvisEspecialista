"""Offline analyzers: secrets, SCA, Nmap XML, NVD JSON, CAN FD, UART/I2C/SPI.
Files must be inside the authorized case scope; nothing is executed or transmitted."""
import json
from cyber_core.errors import CoreError

KINDS = ('secrets', 'sca', 'nmap-xml', 'nvd-json', 'canfd', 'uart', 'i2c', 'spi')
COMMANDS = ('offline-analyze',)
LIMIT = 8 * 1024 * 1024


def configure(sub):
    p = sub.add_parser('offline-analyze', help='Offline analysis of an in-scope file: ' + ', '.join(KINDS))
    p.add_argument('case'); p.add_argument('kind', choices=KINDS); p.add_argument('path')
    p.add_argument('--advisories', help='sca: JSON advisory list inside the case scope')
    p.add_argument('--baud', type=int, default=9600)
    p.add_argument('--parity', choices=('none', 'even', 'odd'), default='none')
    p.add_argument('--cpol', type=int, default=0); p.add_argument('--cpha', type=int, default=0)


def _read(core, case, path):
    resolved = core.authorize(case, path)
    with resolved.open('rb') as handle:
        data = handle.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise CoreError('Input exceeds 8 MiB')
    return resolved, data.decode('utf-8', 'replace')


def execute(core, args):
    path, content = _read(core, args.case, args.path)
    kind = args.kind
    if kind == 'secrets':
        from cyber_core.vulnerability.secrets import scan_secrets
        return scan_secrets(content)
    if kind == 'sca':
        if not args.advisories:
            raise CoreError('--advisories is required for sca')
        from cyber_core.vulnerability.sca import check_dependencies
        _, adv = _read(core, args.case, args.advisories)
        return check_dependencies(path.name, content, json.loads(adv))
    if kind == 'nmap-xml':
        from cyber_core.vulnerability.nmap_xml import parse_nmap_xml
        return parse_nmap_xml(content)
    if kind == 'nvd-json':
        from cyber_core.research.nvd import parse_nvd
        return parse_nvd(content)
    if kind == 'canfd':
        from cyber_core.automotive.canfd import analyze_canfd
        return analyze_canfd(content)
    from cyber_core.protocol import serial
    if kind == 'uart':
        return serial.decode_uart(serial.parse_csv(content, 1), args.baud, parity=args.parity)
    if kind == 'i2c':
        return serial.decode_i2c(serial.parse_csv(content, 2))
    return serial.decode_spi(serial.parse_csv(content, 4), cpol=args.cpol, cpha=args.cpha)
