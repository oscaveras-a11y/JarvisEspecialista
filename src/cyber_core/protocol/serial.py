"""Offline decoders for UART, I2C and SPI from logic-analyzer samples.

Input: list of (t, [levels...]) with integer 0/1 levels. Decoders report what
the samples show; they do not probe hardware.
"""
from cyber_core.errors import CoreError


def parse_csv(text, channels, *, max_rows=2_000_000):
    rows = []
    for number, line in enumerate(text.splitlines(), 1):
        if number == 1 and not line[:1].lstrip('-').isdigit():
            continue
        if not line.strip():
            continue
        if len(rows) >= max_rows:
            raise CoreError('Too many samples')
        parts = line.split(',')
        try:
            rows.append((float(parts[0]), [int(p) for p in parts[1:1 + channels]]))
        except ValueError as exc:
            raise CoreError('Bad sample at line %d' % number) from exc
        if len(rows[-1][1]) != channels or any(v not in (0, 1) for v in rows[-1][1]):
            raise CoreError('Bad channel data at line %d' % number)
    if len(rows) < 2:
        raise CoreError('Not enough samples')
    return rows


def decode_uart(rows, baud, *, parity='none', stop=1):
    if baud <= 0 or parity not in ('none', 'even', 'odd'):
        raise CoreError('Invalid UART settings')
    bit = 1.0 / baud
    out, errors, i, n = [], 0, 1, len(rows)
    while i < n:
        if rows[i - 1][1][0] == 1 and rows[i][1][0] == 0:
            start = rows[i][0]
            def at(t):
                j = i
                while j + 1 < n and rows[j + 1][0] <= t:
                    j += 1
                return rows[j][1][0]
            if rows[-1][0] < start + bit * (9 + (parity != 'none') + stop):
                break
            value = sum(at(start + bit * (k + 1.5)) << k for k in range(8))
            pos = 9.5
            if parity != 'none':
                p = at(start + bit * pos); pos += 1
                ones = bin(value).count('1') + p
                if (ones % 2 == 0) != (parity == 'even'):
                    errors += 1
            if at(start + bit * pos) != 1:
                errors += 1
            out.append(value)
            end = start + bit * (pos + stop - 0.5)
            while i < n and rows[i][0] < end:
                i += 1
            continue
        i += 1
    return {'bytes': bytes(out).hex(), 'count': len(out), 'framing_or_parity_errors': errors}


def decode_i2c(rows):
    """Channels: [SDA, SCL]. Returns transactions as lists of (address/rw or data, ack)."""
    transactions, current, bits = [], None, []
    for k in range(1, len(rows)):
        (_, (sda0, scl0)), (_, (sda1, scl1)) = rows[k - 1], rows[k]
        if scl1 == 1 and scl0 == 1 and sda0 == 1 and sda1 == 0:      # START
            if current:
                transactions.append(current)
            current, bits = [], []
        elif scl1 == 1 and scl0 == 1 and sda0 == 0 and sda1 == 1:    # STOP
            if current is not None:
                transactions.append(current)
            current, bits = None, []
        elif scl0 == 0 and scl1 == 1 and current is not None:         # SCL rising: sample
            bits.append(sda1)
            if len(bits) == 9:
                value = int(''.join(map(str, bits[:8])), 2)
                current.append({'byte': value, 'ack': bits[8] == 0})
                bits = []
    if current:
        transactions.append(current)
    out = []
    for tx in transactions:
        if not tx:
            continue
        first = tx[0]['byte']
        out.append({'address': first >> 1, 'read': bool(first & 1), 'address_ack': tx[0]['ack'],
                    'data': bytes(b['byte'] for b in tx[1:]).hex(), 'nacks': sum(1 for b in tx if not b['ack'])})
    return {'transactions': out}


def decode_spi(rows, *, cpol=0, cpha=0, bits=8):
    """Channels: [CS, CLK, MOSI, MISO]; CS active low."""
    if cpol not in (0, 1) or cpha not in (0, 1) or not 1 <= bits <= 8:
        raise CoreError('Invalid SPI settings')
    frames, mosi, miso, cur_m, cur_i = [], [], [], [], []
    sample_rising = (cpol == cpha)
    for k in range(1, len(rows)):
        cs0, clk0, _, _ = rows[k - 1][1]
        cs1, clk1, mo, mi = rows[k][1]
        if cs0 == 1 and cs1 == 0:
            cur_m, cur_i, mosi, miso = [], [], [], []
        elif cs0 == 0 and cs1 == 1:
            frames.append({'mosi': bytes(mosi).hex(), 'miso': bytes(miso).hex(), 'partial_bits': len(cur_m)})
        elif cs1 == 0 and clk0 != clk1 and ((clk1 == 1) == sample_rising):
            cur_m.append(mo); cur_i.append(mi)
            if len(cur_m) == bits:
                mosi.append(int(''.join(map(str, cur_m)), 2))
                miso.append(int(''.join(map(str, cur_i)), 2))
                cur_m, cur_i = [], []
    return {'frames': frames}
