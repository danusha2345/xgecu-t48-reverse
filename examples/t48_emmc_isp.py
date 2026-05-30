#!/usr/bin/env python3
"""
t48_emmc_isp.py — arbitrary eMMC read/write over the XGecu ISP adapter (1-bit).

This REPLAYS the exact eMMC-ISP flow captured from Xgpro (docs/PROTOCOL.md
§33–§34), parameterised by block address, so we can read/write an arbitrary
region from Linux. Requires the XGecu eMMC-ISP adapter + a connected eMMC
(the adapter announces itself as "XGecu Directly" over opcode 0x24).

Two modes:
  (default)  read-only validation — adapter handshake + init, print CID, then
             read one arbitrary 16 KB chunk and hexdump it. Non-destructive.
  --write-test BLOCK   write a marker pattern to one 16 KB chunk at BLOCK,
             read it back and verify. DESTRUCTIVE (overwrites that chunk).

VCCQ: --voltage 3.3 (default, capture-confirmed) or 1.8. The 1.8 V byte
(BEGIN[0x15]=1) is derived from static reverse of Xgpro.exe and is NOT yet
verified on hardware — only use it on a chip you know is 1.8 V.

Block addressing: 1 block = 512 B; one transfer chunk = 32 blocks = 16 KB.
Bus width is 1-bit (BEGIN bus-width byte 0x51); read+write are hardware-
verified at 3.3 V.

USAGE:
  python3 t48_emmc_isp.py                         # read-only validation @ block 0x8000
  python3 t48_emmc_isp.py --block 0x100000        # read-only @ another block
  python3 t48_emmc_isp.py --write-test 0x8000     # write+read-back verify (DESTRUCTIVE)
  python3 t48_emmc_isp.py --voltage 1.8           # 1.8 V VCCQ (UNVERIFIED)
"""
import argparse, struct, sys, time
import usb.core, usb.util
from t48_emmc import T48Emmc, VID, PID

# ---- exact byte templates captured from Xgpro (1-bit / 3.3 V eMMC ISP) ----
ADAPTER_HS = [bytes.fromhex(x) for x in (
    "24f0000001000000", "24e0280000000000000000e5", "24f1000000000000")]
OP_3E      = bytes.fromhex("3e01100000080000")
BEGIN_READ = bytes.fromhex("033100000005a1002000000051002000000200000000000003000000"
                           "030000000000000000000000000000e51000000000000000000000003808000000000051")
BEGIN_WRITE= bytes.fromhex("033100000005a1002000000051002000000200000000000004000000"
                           "030000000000000000000000000000e51000000000000000000000003808000000007951")
STATUS     = bytes.fromhex("393100000005a100")        # 0x39 -> 32-byte reply
INIT_21    = bytes.fromhex("2100000000000000")        # -> 8-byte OCR-like
READID_05  = bytes.fromhex("0500000000000000")        # -> CID
READCSD_06 = bytes.fromhex("0600000000000000")        # -> CSD/status
EXTCSD_08  = bytes.fromhex("0848000200000000")        # -> 512-byte EXT_CSD on EP2 IN
SWITCH_RPMB = bytes.fromhex("274600000003b301")       # PARTITION_CONFIG -> RPMB (part of arm)
SWITCH_USER = bytes.fromhex("274600000007b302")       # PARTITION_CONFIG -> USER
SWITCH_BOOT1= bytes.fromhex("274600000001b301")       # PARTITION_CONFIG -> BOOT1
SWITCH_BOOT2= bytes.fromhex("274600000002b301")       # PARTITION_CONFIG -> BOOT2
PART_SWITCH = {"USER": SWITCH_USER, "BOOT1": SWITCH_BOOT1,
               "BOOT2": SWITCH_BOOT2, "RPMB": SWITCH_RPMB}
END        = bytes.fromhex("0400000000000000")
RESET      = bytes.fromhex("3f00000000000000")
# read streaming
RD_SETUP   = bytes.fromhex("0d010000000000000002000020000000000100002000000020000000010000000100000000000000")
RD_14      = bytes.fromhex("14000000000000000100000200000000")
RD_15      = bytes.fromhex("15000002000000000100000200000000")
# write
WR_SETUP   = bytes.fromhex("1f010000000000000002000020000000000100002000000020000000040000000100000000000000")
ERASE_4D   = bytes.fromhex("274d010000000100")        # 0x27/0x4D erase-group step

BLK = 512
CHUNK_BLOCKS = 32                 # 16 KB per transfer chunk
CHUNK = CHUNK_BLOCKS * BLK        # 16384


def _set_u32(buf, off, val):
    b = bytearray(buf); struct.pack_into("<I", b, off, val & 0xFFFFFFFF); return bytes(b)


# JEDEC eMMC manufacturer IDs (CID byte[0] AFTER word-swap, see _decode_cid).
_MID = {0x02: "SanDisk", 0x11: "Toshiba/Kioxia", 0x13: "Micron", 0x15: "Samsung",
        0x45: "SanDisk", 0x70: "Kingston", 0x90: "SK Hynix", 0x9B: "YMTC",
        0xD6: "Foresee", 0xFE: "Micron"}


def _decode_cid(reg16):
    """The T48 returns CID/CSD as FOUR 32-bit little-endian words, NOT a flat
    JEDEC MSB-first register. Reading the 16-byte register as-is gives a bogus
    MID and a garbled PNM (and e.g. a 2019 date for a 2024 part). Swapping each
    4-byte word back yields the real register — proven by CRC7 matching only for
    the swapped order. Returns (swapped, manufacturer, pnm, rev, sn, date)."""
    c = b''.join(reg16[i:i + 4][::-1] for i in range(0, 16, 4))
    mid = c[0]
    pnm = ''.join(chr(x) if 32 <= x < 127 else '.' for x in c[3:9])
    rev = f"{c[9] >> 4}.{c[9] & 0xF}"
    sn = int.from_bytes(c[10:14], "big")
    mdt = c[14]
    date = f"{2013 + (mdt >> 4)}-{(mdt & 0xF):02d}"
    return c, _MID.get(mid, f"Unknown(0x{mid:02x})"), pnm, rev, sn, date


class EmmcIsp:
    def __init__(self, log=None, vccq_18=False):
        self.d = T48Emmc(log_path=log)
        self.vccq_18 = vccq_18      # False = 3.3 V (captured), True = 1.8 V

    def _begin(self, base):
        # BEGIN_TRANSACTION byte[0x15] = VCCQ selector (DAT_007485c8 in
        # FUN_00444bc0 @ 0x444edd): 0x00 = 3.3 V, 0x01 = 1.8 V. The 3.3 V
        # value is capture-confirmed; 1.8 V is derived from static reverse
        # (the cmp sites at 0x4953a0/0x493d61 treat it as 0=3.3V/50MHz vs
        # nonzero=1.8V/HS200) and is NOT hardware-verified.
        b = bytearray(base)
        b[0x15] = 0x01 if self.vccq_18 else 0x00
        return bytes(b)

    def connect(self):
        self.d.connect()
        # belt-and-suspenders: clear any leftover pipe STALL from a prior run.
        # NOTE: if the programmer's eMMC state machine is wedged (e.g. an
        # aborted mid-session transfer), neither this nor a USB reset recovers
        # it — only a physical unplug/replug does.
        for ep in (0x01, 0x81, 0x02, 0x82):
            try: self.d.dev.clear_halt(ep)
            except Exception: pass

    def close(self):
        # leave the session ended; do NOT send RESET (0x3f) here — it leaves
        # the programmer briefly unresponsive and stalls the next session's
        # first transfer. Recovery is handled by clear_halt in _drain().
        self.d.close()

    # ---- session pieces (replayed) ----
    def _adapter_and_init(self, begin):
        # adapter identity is queued after 24e0, before 24f1 (reply is 63 B —
        # always over-read with a 512-byte buffer to avoid libusb Overflow).
        self.d.ep1_send(ADAPTER_HS[0])
        self.d.ep1_send(ADAPTER_HS[1])
        ident = self.d.ep1_recv(512)
        self.d.ep1_send(ADAPTER_HS[2])
        self.d.ep1_send(OP_3E); self.d.ep1_recv(512)
        self.d.ep1_send(begin)
        self.d.ep1_send(STATUS); st = self.d.ep1_recv(64)
        if len(st) > 12 and (st[12] & 1):
            raise RuntimeError("OVC tripped after BEGIN")
        self.d.ep1_send(INIT_21);   ocr = self.d.ep1_recv(64)
        self.d.ep1_send(READID_05); cid = self.d.ep1_recv(64)
        self.d.ep1_send(READCSD_06); csd = self.d.ep1_recv(64)
        # EXT_CSD: 512-byte block + an 8-byte ack, BOTH on EP2 IN (not EP1)
        self.d.ep1_send(EXTCSD_08); _ = self.d.ep2_recv(512); self.d.ep2_recv(8)
        return {"ident": ident, "ocr": ocr, "cid": cid, "csd": csd}

    def _arm_bulk(self):
        # one-time arm before reads — actually a 512-byte RPMB probe:
        # SWITCH->RPMB, 0x14, [512 B on EP2 OUT], 0x15, [512 B + 16 B on EP2 IN],
        # then SWITCH->USER. (capture frames 141-155)
        self.d.ep1_send(SWITCH_RPMB); self.d.ep1_recv(64)
        self.d.ep1_send(RD_14)
        self.d.ep2_send(b"\x00" * 512)
        self.d.ep1_send(RD_15)
        self.d.ep2_recv(512)
        self.d.ep2_recv(16)
        self.d.ep1_send(SWITCH_USER); self.d.ep1_recv(64)

    def _teardown(self):
        """Guarantee the FPGA is never left mid-transfer. A stuck FPGA->host
        bulk is the cause of the hard wedge; draining pending IN completes it,
        then END closes the session. Called on ANY error inside a session."""
        for ep in (0x82, 0x81):
            for _ in range(6):
                try:
                    if not self.d.dev.read(ep, 16384, timeout=400): break
                except usb.core.USBError: break
        try: self.d.ep1_send(END)
        except Exception: pass

    # ---- arbitrary read (USER / BOOT1 / BOOT2) ----
    def _read_once(self, start_block, n_chunks, part="USER"):
        try:
            info = self._adapter_and_init(self._begin(BEGIN_READ))
            self._arm_bulk()                       # arm ends on USER
            if part != "USER":
                self.d.ep1_send(PART_SWITCH[part]); self.d.ep1_recv(64)
            setup = _set_u32(_set_u32(RD_SETUP, 4, start_block), 16, n_chunks)
            self.d.ep1_send(setup)
            data = bytearray()
            for _ in range(n_chunks):
                # each chunk: [16-byte header + 16368 data] then [16 data];
                # join header[16:] + tail -> 16384 real bytes
                big = self.d.ep2_recv(CHUNK)
                tail = self.d.ep2_recv(16)
                data += big[16:] + tail
            self.d.ep1_send(END)
            return info, bytes(data[:n_chunks * CHUNK])
        except Exception:
            self._teardown(); raise

    # ---- arbitrary write (USER / BOOT1 / BOOT2) ----
    def _write_once(self, start_block, data, erase=False, part="USER"):
        assert len(data) % CHUNK == 0, "data must be a multiple of 16 KB"
        n_chunks = len(data) // CHUNK
        try:
            info = self._adapter_and_init(self._begin(BEGIN_WRITE))
            self.d.ep1_send(PART_SWITCH[part]); self.d.ep1_recv(64)
            if erase:
                # erase the 1024-block (512 KB) groups covering the region
                g0 = start_block & ~0x3FF
                g1 = (start_block + n_chunks * CHUNK_BLOCKS - 1) & ~0x3FF
                for g in range(g0, g1 + 1, 0x400):
                    self.d.ep1_send(ERASE_4D); self.d.ep1_recv(64)
                    er = bytearray(16); er[0] = 0x0E
                    struct.pack_into("<I", er, 4, g)
                    struct.pack_into("<I", er, 8, g + 0x3FF)
                    self.d.ep1_send(bytes(er)); self.d.ep1_recv(64)
            setup = _set_u32(WR_SETUP, 16, n_chunks)
            self.d.ep1_send(setup)
            for i in range(n_chunks):
                blk = start_block + i * CHUNK_BLOCKS
                hdr = struct.pack("<IIHHI", 0, blk, BLK, 0, CHUNK_BLOCKS)
                self.d.ep2_send(hdr + data[i * CHUNK:(i + 1) * CHUNK])
            self.d.ep1_send(STATUS); self.d.ep1_recv(64)
            self.d.ep1_send(END)
            return info
        except Exception:
            self._teardown(); raise

    # ---- recovery + retry ----
    def _recover(self):
        """Best-effort recovery after a failed transfer. Works for transient
        init/timeout hiccups; a HARD wedge (aborted mid-bulk) survives this and
        only a physical replug clears it. Returns True if the programmer pings
        back (alive)."""
        for ep in (0x01, 0x81, 0x02, 0x82):
            try: self.d.dev.clear_halt(ep)
            except Exception: pass
        for ep in (0x81, 0x82):              # drain stale IN
            for _ in range(20):
                try:
                    if not self.d.dev.read(ep, 16384, timeout=150): break
                except Exception: break
        try: self.d.ep1_send(END)
        except Exception: pass
        try:                                  # programmer identify (non-eMMC) = alive check
            self.d.ep1_send(b"\x00" * 8)
            return len(self.d.ep1_recv(512)) > 0
        except Exception:
            return False

    def _retry(self, fn, attempts=3):
        last = None
        for _ in range(attempts):
            try:
                return fn()
            except usb.core.USBError as ex:
                last = ex
                if not self._recover():
                    raise RuntimeError("T48 wedged — physically unplug/replug it") from ex
        raise last

    def read(self, start_block, n_chunks, part="USER"):
        return self._retry(lambda: self._read_once(start_block, n_chunks, part))

    def write(self, start_block, data, erase=False, part="USER"):
        return self._retry(lambda: self._write_once(start_block, data, erase, part))

    # ---- friendly region API (arbitrary block offset / length) ----
    def read_region(self, start_block, n_blocks, part="USER"):
        """Read n_blocks*512 bytes from start_block (any block, not just
        16 KB-aligned)."""
        base = start_block - (start_block % CHUNK_BLOCKS)
        off = (start_block - base) * BLK
        n_chunks = (off + n_blocks * BLK + CHUNK - 1) // CHUNK
        _, data = self.read(base, n_chunks, part)
        return data[off:off + n_blocks * BLK]

    def write_region(self, start_block, data, erase=False, part="USER"):
        """Write `data` starting at start_block (any block/length). Edges that
        don't fall on a 16 KB chunk are read-modify-written so neighbours are
        preserved."""
        base = start_block - (start_block % CHUNK_BLOCKS)
        off = (start_block - base) * BLK
        total = off + len(data)
        n_chunks = (total + CHUNK - 1) // CHUNK
        if off == 0 and len(data) % CHUNK == 0:
            buf = bytearray(data)                       # fully aligned: no RMW
        else:
            buf = bytearray(self.read(base, n_chunks, part)[1])  # RMW: fetch covering chunks
            buf[off:off + len(data)] = data
            buf += b"\x00" * (n_chunks * CHUNK - len(buf))
        self.write(base, bytes(buf[:n_chunks * CHUNK]), erase=erase, part=part)


def parse_partitions(buf):
    """Parse MBR / GPT from the first sectors of the USER area.
    Returns (scheme, [(name, first_lba, last_lba)])."""
    mbr, gpt = buf[0:512], buf[512:1024]
    if gpt[:8] == b"EFI PART":
        entry_lba = struct.unpack_from("<Q", gpt, 72)[0]
        num = struct.unpack_from("<I", gpt, 80)[0]
        esize = struct.unpack_from("<I", gpt, 84)[0]
        out = []
        for i in range(min(num, 256)):
            o = entry_lba * BLK + i * esize
            if o + esize > len(buf):
                break
            e = buf[o:o + esize]
            if e[:16] == b"\x00" * 16:
                continue
            first = struct.unpack_from("<Q", e, 32)[0]
            last = struct.unpack_from("<Q", e, 40)[0]
            name = e[56:128].decode("utf-16-le", "replace").rstrip("\x00")
            out.append((name or "(unnamed)", first, last))
        return "GPT", out
    if mbr[510:512] == b"\x55\xaa":
        out = []
        for i in range(4):
            p = mbr[446 + i * 16: 446 + (i + 1) * 16]
            if p[4] == 0:
                continue
            start = struct.unpack_from("<I", p, 8)[0]
            cnt = struct.unpack_from("<I", p, 12)[0]
            out.append(("type=0x%02x" % p[4], start, start + cnt - 1))
        return "MBR", out
    return "none", []


def fs_magic(sec):
    """Best-effort filesystem sniff from a partition's first 2 KB."""
    if len(sec) >= 0x440 and sec[0x438:0x43a] == b"\x53\xef":
        return "ext2/3/4"
    if sec[0:4] == b"ANDR":
        return "android-boot-img"
    if sec[0:8] == b"\x88\x16\x88\x58" or sec[0:4] == b"\x3a\xff\x26\xed":
        return "sparse/erofs?"
    if sec[0:6] == b"\xe2\xe1\xf5\xe0\x00\x00":
        return "f2fs"
    if (sec[0x36:0x3b] == b"FAT16" or sec[0x52:0x57] == b"FAT32"
            or sec[0:3] == b"\xeb\x3c\x90"):
        return "FAT"
    if sec[0:4] == b"\x53\xef\x71\x10":
        return "?"
    if sec.count(0) > len(sec) - 4:
        return "(blank)"
    return "?"


def _hexdump(b, n=128):
    out = []
    for o in range(0, min(len(b), n), 16):
        c = b[o:o+16]
        out.append(f"  {o:04x}  {' '.join('%02x'%x for x in c):<48}  "
                   + ''.join(chr(x) if 32 <= x < 127 else '.' for x in c))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--block", type=lambda x: int(x, 0), default=0x8000,
                    help="start block (512 B units) for read-only validation")
    ap.add_argument("--write-test", type=lambda x: int(x, 0), metavar="BLOCK",
                    help="DESTRUCTIVE: write a marker to one 16KB chunk at BLOCK and verify")
    ap.add_argument("--partitions", action="store_true",
                    help="read the USER partition table (MBR/GPT) and list partitions + FS")
    ap.add_argument("--boot-roundtrip", action="store_true",
                    help="read BOOT1/BOOT2, write the same bytes back, re-read and verify")
    ap.add_argument("--erase", action="store_true", help="erase the region before write")
    ap.add_argument("--voltage", choices=("3.3", "1.8"), default="3.3",
                    help="VCCQ I/O voltage: 3.3 (capture-confirmed) or 1.8 "
                         "(static-reverse, UNVERIFIED on hardware)")
    ap.add_argument("--log", default="t48_emmc_isp.log")
    args = ap.parse_args()

    e = EmmcIsp(log=args.log, vccq_18=(args.voltage == "1.8"))
    print(f"   VCCQ = {args.voltage} V"
          + ("  [1.8 V is static-reverse-derived, not hardware-verified]"
             if args.voltage == "1.8" else ""))
    e.connect()
    try:
        if args.partitions:
            # --- read partition table from the USER area, list partitions + FS ---
            print("== USER partition table ==")
            head = e.read_region(0, 64)          # LBA 0..63 covers MBR + GPT(+entries)
            scheme, parts = parse_partitions(head)
            print(f"  scheme: {scheme}, {len(parts)} partition(s)")
            for name, first, last in parts:
                mb = (last - first + 1) * BLK / (1024 * 1024)
                fs = "?"
                try:
                    fs = fs_magic(e.read_region(first, 4))   # first 2 KB of the partition
                except Exception as ex:
                    fs = f"(read failed: {type(ex).__name__})"
                print(f"  {name:<20} LBA {first:>10}..{last:<10} {mb:8.1f} MiB  fs={fs}")
            print("\n[OK] partition table read from Linux." if parts
                  else "\n[CHECK] no MBR/GPT found at LBA 0/1.")
        elif args.boot_roundtrip:
            # --- read boot partitions, write the same bytes back, verify ---
            for part in ("BOOT1", "BOOT2"):
                print(f"== {part} read -> write-back -> verify (64 KB) ==")
                orig = e.read_region(0, 128, part=part)        # 128 blocks = 64 KB
                print(f"  [1] read {len(orig)} B  head={orig[:16].hex()}")
                e.write_region(0, orig, part=part)
                print("  [2] wrote the same bytes back")
                again = e.read_region(0, 128, part=part)
                print(f"  [3] re-read matches original: {again == orig}")
        elif args.write_test is None:
            # --- non-destructive validation ---
            print(f"== read-only validation @ block 0x{args.block:x} (16 KB) ==")
            info, data = e.read(args.block, 1)
            reg = info["cid"][8:24] if len(info["cid"]) >= 24 else info["cid"]
            _, man, pnm, rev, sn, date = _decode_cid(reg)
            print(f"  adapter ident : {info['ident'][8:].split(bytes([0]))[0].decode('latin1','replace')!r}")
            print(f"  CID (raw 16B) : {reg.hex()}  (32-bit LE words — see _decode_cid)")
            print(f"  CID (decoded) : {man} '{pnm}' Rev={rev} SN=0x{sn:08x} Date={date}")
            print(f"  OCR-like      : {info['ocr'].hex()}")
            print(f"  data @0x{args.block:x}:")
            print(_hexdump(data))
            print("\n[OK] adapter + init + arbitrary read work from Linux.")
        else:
            blk = args.write_test
            print(f"== arbitrary write+read @ block 0x{blk:x} (16 KB), erase={args.erase} ==")
            pattern = (b"XGECU-T48-ISP-RW-" + bytes([blk & 0xFF])) * (CHUNK // 18)
            pattern = (pattern + b"\x00" * CHUNK)[:CHUNK]
            e.write(blk, pattern, erase=args.erase)
            print("  [1] wrote 16 KB test pattern")
            _, rb = e.read(blk, 1)
            ok = rb == pattern
            print(f"  [2] read back -> matches written pattern: {ok}")
            print(_hexdump(rb))
            print(f"\n[{'OK' if ok else 'CHECK'}] arbitrary write+read "
                  f"{'VERIFIED' if ok else 'needs review'}.")
    finally:
        e.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
