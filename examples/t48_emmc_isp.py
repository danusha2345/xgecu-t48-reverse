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

    # ---- arbitrary read (USER partition) ----
    def _read_once(self, start_block, n_chunks):
        info = self._adapter_and_init(self._begin(BEGIN_READ))
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
    def _write_once(self, start_block, data, erase=False):
        assert len(data) % CHUNK == 0, "data must be a multiple of 16 KB"
        n_chunks = len(data) // CHUNK
        info = self._adapter_and_init(self._begin(BEGIN_WRITE))
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

    def read(self, start_block, n_chunks):
        return self._retry(lambda: self._read_once(start_block, n_chunks))

    def write(self, start_block, data, erase=False):
        return self._retry(lambda: self._write_once(start_block, data, erase))

    # ---- friendly region API (arbitrary block offset / length) ----
    def read_region(self, start_block, n_blocks):
        """Read n_blocks*512 bytes from start_block (any block, not just
        16 KB-aligned)."""
        base = start_block - (start_block % CHUNK_BLOCKS)
        off = (start_block - base) * BLK
        n_chunks = (off + n_blocks * BLK + CHUNK - 1) // CHUNK
        _, data = self.read(base, n_chunks)
        return data[off:off + n_blocks * BLK]

    def write_region(self, start_block, data, erase=False):
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
            buf = bytearray(self.read(base, n_chunks)[1])   # RMW: fetch covering chunks
            buf[off:off + len(data)] = data
            buf += b"\x00" * (n_chunks * CHUNK - len(buf))
        self.write(base, bytes(buf[:n_chunks * CHUNK]), erase=erase)


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
