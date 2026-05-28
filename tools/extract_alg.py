#!/usr/bin/env python3
"""
extract_alg.py — unpacker for XGecu Xgpro `*.alg` algorithm files.

Each `.alg` ships one compressed FPGA bitstream for one chip family in
the T48 / T56 / T76 programmer. This script decompresses it to the
raw 340604-byte payload (Xilinx Spartan-6 LX9 class).

File format (reverse-engineered, see docs/PROTOCOL.md):

    0x000        char[N]   algorithm-family name, ASCII, \\0-terminated
                           (e.g. "EMMC211210", "EMMC18", "SPI-18", "AT45DB")
    0x000..0x220 zero-pad  header padded with zeros
    0x220        u32 LE    decompressed bitstream size = 340604 (0x5327C)
    0x224        u32 LE    CRC32 of compressed data = zlib.crc32(comp) ^ 0xFFFFFFFF
    0x228        …         compressed bitstream — zero-RLE over 16-bit words:
                             read u16 val;
                             if val != 0: emit val
                             else:       read u16 len; emit `len` zero-words

The decompressed payload starts with a 16-byte 0xFF preamble followed
by the Xilinx Spartan-6 sync word `AA 99 55 66`.

Usage:
    python3 extract_alg.py path/to/EMMC_53_18.alg                    # -> EMMC_53_18.bit
    python3 extract_alg.py file.alg --output decoded.bin --verbose
    python3 extract_alg.py *.alg                                      # batch mode
"""
import argparse
import os
import struct
import sys
import zlib


SIZE_OFFSET = 0x220
CRC_OFFSET  = 0x224
DATA_OFFSET = 0x228
EXPECTED_DECOMPRESSED_SIZE = 0x5327C    # 340604 bytes; Spartan-6 LX9-class bitstream


def extract(path: str, verify: bool = True) -> tuple[str, bytes]:
    """Decompress a `.alg` file and return (algorithm_name, raw_bitstream)."""
    with open(path, 'rb') as f:
        d = f.read()

    if len(d) < DATA_OFFSET + 4:
        raise ValueError(f"file too short: {len(d)} bytes < {DATA_OFFSET + 4}")

    # Algorithm name is the null-terminated ASCII string at the start.
    zero = d.index(0)
    name = d[:zero].decode('latin1', errors='replace')

    size = struct.unpack_from('<I', d, SIZE_OFFSET)[0]
    crc  = struct.unpack_from('<I', d, CRC_OFFSET)[0]
    comp = d[DATA_OFFSET:]

    if verify:
        calculated_crc = (zlib.crc32(comp) ^ 0xFFFFFFFF) & 0xFFFFFFFF
        if calculated_crc != crc:
            raise ValueError(
                f"CRC mismatch: file says 0x{crc:08x}, "
                f"calculated 0x{calculated_crc:08x}")

    # Zero-RLE decompression over 16-bit words.
    out = bytearray()
    n = len(comp) & ~1
    i = 0
    while i < n:
        val = comp[i] | (comp[i+1] << 8)
        i += 2
        if val != 0:
            out += bytes((val & 0xFF, val >> 8))
        else:
            if i + 1 >= n:
                break
            ln = comp[i] | (comp[i+1] << 8)
            i += 2
            out += b'\x00\x00' * ln

    if verify and len(out) != size:
        raise ValueError(
            f"decompressed size mismatch: header says {size}, got {len(out)}")

    return name, bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract raw FPGA bitstream from Xgpro .alg file(s).")
    ap.add_argument('files', nargs='+', help='one or more .alg files')
    ap.add_argument('-o', '--output',
                    help='output file (only with single input)')
    ap.add_argument('--no-verify', action='store_true',
                    help='skip CRC and size verification')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    if args.output and len(args.files) != 1:
        ap.error("--output works only with a single input file")

    rc = 0
    for path in args.files:
        try:
            name, raw = extract(path, verify=not args.no_verify)
        except Exception as e:
            print(f"{path}: ERROR: {e}", file=sys.stderr)
            rc = 1
            continue

        if args.output:
            out_path = args.output
        else:
            out_path = os.path.splitext(path)[0] + '.bit'

        with open(out_path, 'wb') as f:
            f.write(raw)

        if args.verbose:
            # Look for the sync word in both canonical and byte-rotated forms.
            sync_std = raw.find(b'\xaa\x99\x55\x66')
            sync_alt = raw.find(b'\x99\x55\x66\xaa')
            preamble = "FF×16 OK" if raw[:16] == b'\xff'*16 else "no FF preamble"
            sync_str = (f"sync@0x{sync_std:x}" if sync_std >= 0
                        else f"alt-sync@0x{sync_alt:x}" if sync_alt >= 0
                        else "no sync found")
            print(f"{path}: name='{name}', size={len(raw)}, "
                  f"{preamble}, {sync_str}, written to {out_path}")
        else:
            print(f"{path}: {name} -> {out_path} ({len(raw)} bytes)")

    return rc


if __name__ == '__main__':
    sys.exit(main())
