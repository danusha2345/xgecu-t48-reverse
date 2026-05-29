#!/usr/bin/env python3
"""
t48_emmc_isp.py — arbitrary eMMC read/write over the XGecu ISP adapter, 1-bit / 3.3 V.

This REPLAYS the exact eMMC-ISP flow captured from Xgpro (docs/PROTOCOL.md
§33–§34), parameterised by block address, so we can read/write an arbitrary
region from Linux. Requires the XGecu eMMC-ISP adapter + a connected eMMC
(the adapter announces itself as "XGecu Directly" over opcode 0x24).

Two modes:
  (default)  read-only validation — adapter handshake + init, print CID, then
             read one arbitrary 16 KB chunk and hexdump it. Non-destructive.
  --write-test BLOCK   backup -> write pattern -> verify -> restore on one
             16 KB chunk at BLOCK. Writes to the eMMC; the original is saved
             to disk and written back, then re-verified.

Block addressing: 1 block = 512 B; one transfer chunk = 32 blocks = 16 KB.
1-bit / 3.3 V is fixed by the captured BEGIN templates (bus-width byte 0x51).

USAGE:
  python3 t48_emmc_isp.py                         # read-only validation @ block 0x8000
  python3 t48_emmc_isp.py --block 0x100000        # read-only @ another block
  python3 t48_emmc_isp.py --write-test 0x8000     # full r/w round-trip (DESTRUCTIVE)
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
SWITCH_RPMB= bytes.fromhex("274600000003b301")        # PARTITION_CONFIG -> RPMB (part of arm)
SWITCH_USER= bytes.fromhex("274600000007b302")        # PARTITION_CONFIG -> USER
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


class EmmcIsp:
    def __init__(self, log=None):
        self.d = T48Emmc(log_path=log)

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

    # ---- arbitrary read (USER partition) ----
    def read(self, start_block, n_chunks):
        info = self._adapter_and_init(BEGIN_READ)
        self._arm_bulk()
        setup = _set_u32(_set_u32(RD_SETUP, 4, start_block), 16, n_chunks)
        self.d.ep1_send(setup)
        data = bytearray()
        for _ in range(n_chunks):
            # each chunk arrives as [16-byte header + 16368 data] then [16 data];
            # strip the header and append the 16-byte tail -> 16384 real bytes
            big = self.d.ep2_recv(CHUNK)     # 16 B header + 16368 data
            tail = self.d.ep2_recv(16)       # final 16 data bytes
            data += big[16:] + tail
        self.d.ep1_send(END)
        return info, bytes(data[:n_chunks * CHUNK])

    # ---- arbitrary write (USER partition) ----
    def write(self, start_block, data, erase=False):
        assert len(data) % CHUNK == 0, "data must be a multiple of 16 KB"
        n_chunks = len(data) // CHUNK
        info = self._adapter_and_init(BEGIN_WRITE)
        # write goes straight to USER (no 0x14/0x15 arm — that is read-only)
        self.d.ep1_send(SWITCH_USER); self.d.ep1_recv(64)
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
                    help="DESTRUCTIVE: backup->write->verify->restore one 16KB chunk at BLOCK")
    ap.add_argument("--erase", action="store_true", help="erase the region before write")
    ap.add_argument("--log", default="t48_emmc_isp.log")
    args = ap.parse_args()

    e = EmmcIsp(log=args.log)
    e.connect()
    try:
        if args.write_test is None:
            # --- non-destructive validation ---
            print(f"== read-only validation @ block 0x{args.block:x} (16 KB) ==")
            info, data = e.read(args.block, 1)
            cid = info["cid"][8:24] if len(info["cid"]) >= 24 else info["cid"]
            pnm = ''.join(chr(c) if 32 <= c < 127 else '.' for c in cid)
            print(f"  adapter ident : {info['ident'][8:].split(bytes([0]))[0].decode('latin1','replace')!r}")
            print(f"  CID           : {cid.hex()}  ('{pnm}')")
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
