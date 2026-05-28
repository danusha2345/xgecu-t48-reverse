#!/usr/bin/env python3
"""
t48_emmc.py — pyusb prototype for talking to the XGecu T48 programmer
with focus on eMMC ISP operations.

Status: DRAFT. Built before having hardware on hand, on the basis of
static reverse engineering of Xgpro.exe. See docs/PROTOCOL.md for the
full write-up.

When the T48 finally arrives:
  1. Run `python3 t48_emmc.py --connect` — the device should open at
     VID:PID a466:0a53.
  2. Cross-check the bytes the device returns for each high-level call
     against what this file expects.
  3. Walk through every TODO using a USB capture as ground truth.

Dependencies: pip install pyusb  (with libusb-1.0 installed on Linux)
"""
import struct
import time
import random
from typing import Optional

try:
    import usb.core
    import usb.util
except ImportError:
    raise SystemExit("pyusb not installed — run: pip install pyusb")


# ============================================================
# USB identity
# ============================================================
VID = 0xA466
PID = 0x0A53

# Endpoint pipe IDs, recovered from Ghidra-decompiled raw helpers in Xgpro.exe.
# After full decompilation we discovered Xgpro uses up to FIVE pipes for some
# transfers; for eMMC we only care about EP1 (bidirectional) and EP2 OUT/IN:
EP1_OUT = 0x01    # short commands, bulk-read setup (sub_4dc380 always uses pipe 1)
EP1_IN  = 0x81    # short responses (sub_4dc300 always uses pipe 0x81)
EP2_OUT = 0x02    # bulk-write payload for eMMC (RPMB frames / CMD25 data)
EP2_IN  = 0x82    # bulk-read responses for eMMC and VGA (Format B and some D paths!)
# EP3 OUT (pipe 3) and EP5 OUT (pipe 5) also exist for parallel-transfer and
# VGA paths respectively — not relevant for the eMMC ISP flow we care about.


# ============================================================
# T48 protocol opcodes (unified table)
# Sources:
#   - minipro/src/t48.c          → classic opcodes 0x02..0x3F
#   - reverse of Xgpro.exe       → eMMC extension (0x08, 0x14, 0x21, 0x27)
# ============================================================
class TopOp:
    """Top-opcode = byte[0] of any EP1 command packet."""
    # Classic (from minipro/src/t48.c)
    NAND_INIT       = 0x02
    BEGIN_TRANS     = 0x03
    END_TRANS       = 0x04
    READID          = 0x05    # identify; also used by Xgpro eMMC init
    READ_USER       = 0x06    # config zone; also used by Xgpro eMMC init
    READ_CFG        = 0x08    # in eMMC this becomes the long-recv envelope
    WRITE_CFG       = 0x09
    READ_DATA       = 0x10
    WRITE_DATA      = 0x11
    SET_VCC_VOLTAGE = 0x1B
    SET_VPP_VOLTAGE = 0x1C
    REQUEST_STATUS  = 0x39
    RESET           = 0x3F
    # eMMC extension (Xgpro only)
    EMMC_BULK_WRITE_SETUP = 0x14    # 16-byte setup before N×512 on EP2 OUT
    EMMC_INIT_SELECT      = 0x21    # eMMC init / algorithm select
    EMMC_LONG_RECV        = 0x08    # envelope for requests with large recv
    EMMC_SUBCMD           = 0x27    # eMMC sub-command dispatcher (byte[1]=sub-op)


class EmmcSubOp:
    """Sub-opcode = byte[1] under top-opcode 0x27."""
    SWITCH          = 0x46    # CMD6 SWITCH (arg = BE-encoded JEDEC argument)
    STOP_AND_STATUS = 0x4C    # CMD12 STOP + CMD13 SEND_STATUS
    COMMIT          = 0x4D    # finalize FPGA (password / RPMB write)
    DATA_BLOCK_512  = 0x50    # 512-byte data transfer (CMD24 / OTP / RPMB data)
    SET_BLOCK_COUNT = 0x57    # CMD23 SET_BLOCK_COUNT (arg = count, usually 1)
    READ_WGP_TABLE  = 0x5D    # read Write-Group Protection table


class LongRecvSubOp:
    """Sub-opcode = byte[1] under top-opcode 0x08."""
    READ_BLOCK_512 = 0x48     # CMD8 SEND_EXT_CSD / CMD17 READ_SINGLE_BLOCK


# ============================================================
# JEDEC eMMC constants
# ============================================================
class Ecsd:
    """EXT_CSD field indices we care about."""
    HS_TIMING        = 0xAF   # 175 — speed-mode select
    PARTITION_CONFIG = 0xB3   # 179 — selects the active partition
    BUS_WIDTH        = 0xB7   # 183
    BOOT_BUS_WIDTH   = 0xB1   # 177
    USER_WP          = 0xAA   # 170
    BOOT_WP          = 0xAD   # 173


class PartAccess:
    """PARTITION_CONFIG[2:0] — partition selected for CMD17/18/24/25."""
    USER  = 0b000
    BOOT1 = 0b001
    BOOT2 = 0b010
    RPMB  = 0b011
    GPP1  = 0b100
    GPP2  = 0b101
    GPP3  = 0b110
    GPP4  = 0b111


class SwitchAccess:
    """Access field of the JEDEC CMD6 SWITCH argument."""
    CMD_SET    = 0x00
    SET_BITS   = 0x01
    CLEAR_BITS = 0x02
    WRITE_BYTE = 0x03


def make_switch_arg(access: int, index: int, value: int, cmd_set: int = 0) -> int:
    """
    Pack the argument for sub-opcode 0x46 (CMD6 SWITCH).

    The result is a DWORD whose high byte is `access`, just like the JEDEC
    CMD6 argument. Verified against the disassembly: this returns the same
    immediate that Xgpro pushes onto the stack before calling 0x492f30.
    For example, 0x01B30300 = SET_BITS, PARTITION_CONFIG (0xB3), Value=0x03
    (= switch to RPMB).
    """
    return (((access  & 0xFF) << 24)
          | ((index   & 0xFF) << 16)
          | ((value   & 0xFF) << 8)
          |  (cmd_set & 0xFF))


# ============================================================
# Packet structures
# ============================================================
def pack_cmd_A(opcode: int, arg: int) -> bytes:
    """
    Format A: 8-byte EP1 command packet, top-opcode 0x27.
    Used through wrapper 0x492f30 in Xgpro.exe.
    """
    return struct.pack('<BBHI', 0x27, opcode & 0xFF, 0x0000, arg & 0xFFFFFFFF)


def pack_cmd_B(opcode: int, length: int, arg: int) -> bytes:
    """
    Format B: 8-byte EP1 command packet, top-opcode 0x08.
    Used through wrapper 0x492900 — for requests with a large recv reply
    (e.g. CMD8 SEND_EXT_CSD returns 512 bytes).
    """
    return struct.pack('<BBHI', 0x08, opcode & 0xFF, length & 0xFFFF, arg & 0xFFFFFFFF)


def pack_bulk_read_setup(count: int) -> bytes:
    """
    Format D: 16-byte setup packet for bulk read. Magic in bytes[0..4]
    is 0x02000015. The reply lands on EP1 IN as 16 bytes of header
    followed by count*512 bytes of data.
    """
    return (struct.pack('<I', 0x02000015)
          + struct.pack('<I', 0)
          + struct.pack('<HH', count & 0xFFFF, 0x0200)
          + struct.pack('<H', 0)
          + b'\x00\x00')


def pack_bulk_write_setup(opcode: int, count: int, block_addr: int) -> bytes:
    """
    Format C setup: 16-byte EP1 packet sent before pushing N×512 bytes
    on EP2 OUT. Magic 0x14 confirmed by disassembly of 0x492670. The
    layout of the remaining fields is partially inferred — refine
    against a USB capture.
    """
    return (struct.pack('<BBHI', 0x14, opcode & 0xFF, count & 0xFFFF, block_addr & 0xFFFFFFFF)
          + struct.pack('<HHHH', 0, 0, 0, 0))


def build_rpmb_frame(req: int, address: int, block_count: int, write_counter: int,
                     data: bytes = b'\x00' * 256,
                     key_mac: bytes = b'\x00' * 32,
                     nonce: Optional[bytes] = None) -> bytes:
    """
    Build a 512-byte JEDEC RPMB frame ready to be transmitted on EP2 OUT.
    The layout is confirmed against the disassembly of wrapper 0x492670.

    req: RPMB request code, one of
        0x0001 = program_key
        0x0002 = read_wc
        0x0003 = auth_data_write
        0x0004 = auth_data_read
        0x0005 = read_result
    """
    if nonce is None:
        nonce = bytes(random.randint(0, 255) for _ in range(16))
    assert len(data) == 256
    assert len(key_mac) == 32
    assert len(nonce) == 16

    frame = bytearray(512)
    # [0x000..0x0C4] stuff bytes — left as zeros
    frame[0x0C4:0x0E4] = key_mac
    frame[0x0E4:0x1E4] = data
    frame[0x1E4:0x1F4] = nonce
    struct.pack_into('>I', frame, 0x1F4, write_counter)     # BE write counter
    struct.pack_into('<H', frame, 0x1F8, address & 0xFFFF)
    struct.pack_into('<H', frame, 0x1FA, block_count & 0xFFFF)
    struct.pack_into('<H', frame, 0x1FC, 0)                  # result
    struct.pack_into('<H', frame, 0x1FE, req & 0xFFFF)       # request/response
    return bytes(frame)


# ============================================================
# High-level eMMC operations (drafts)
# ============================================================
class T48Emmc:
    def __init__(self):
        self.dev = None
        self.read_timeout_ms = 5000

    def connect(self) -> None:
        self.dev = usb.core.find(idVendor=VID, idProduct=PID)
        if self.dev is None:
            raise RuntimeError(f"XGecu T48 not found (VID={VID:04x} PID={PID:04x})")
        # On Linux the WinUSB device is opened directly through libusb.
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        self.dev.set_configuration()
        usb.util.claim_interface(self.dev, 0)
        print(f"[+] T48 opened: {self.dev}")

    def close(self) -> None:
        if self.dev:
            try: usb.util.release_interface(self.dev, 0)
            except Exception: pass
            self.dev = None

    # ---- raw EP1 / EP2 ----
    def ep1_send(self, data: bytes) -> int:
        return self.dev.write(EP1_OUT, data, timeout=self.read_timeout_ms)
    def ep1_recv(self, n: int) -> bytes:
        return bytes(self.dev.read(EP1_IN, n, timeout=self.read_timeout_ms))
    def ep2_send(self, data: bytes) -> int:
        return self.dev.write(EP2_OUT, data, timeout=self.read_timeout_ms)
    def ep2_recv(self, n: int) -> bytes:
        # Used for Format B (top-opcode 0x08) responses in eMMC mode.
        return bytes(self.dev.read(EP2_IN, n, timeout=self.read_timeout_ms))

    # ---- control commands ----
    def switch_partition(self, partition_access: int) -> bytes:
        """CMD6 SWITCH — select the active partition (BOOT1/BOOT2/RPMB/USER/GPP)."""
        arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, partition_access & 0x07)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)   # TODO: exact reply size — confirm with USB capture

    def restore_user_access(self) -> bytes:
        """Clear PARTITION_ACCESS bits [2:0] → return to USER."""
        arg = make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)

    def set_hs200(self) -> bytes:
        """CMD6: HS_TIMING = 0x01 (HS-200)."""
        arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)
        self.ep1_send(pack_cmd_A(EmmcSubOp.SWITCH, arg))
        return self.ep1_recv(8)

    def read_ecsd(self) -> bytes:
        """CMD8 SEND_EXT_CSD — read the 512-byte EXT_CSD.

        Ghidra-confirmed in 0x492900 (cmd_wrapper_0x08): for eMMC (chip_type==7)
        the reply comes back on EP2 IN, with size = length + 8 (the trailing
        8 bytes are a status/header footer that the wrapper does not strip).
        """
        self.ep1_send(pack_cmd_B(LongRecvSubOp.READ_BLOCK_512, 0x200, 0))
        return self.ep2_recv(0x200 + 8)

    def set_block_count(self, n: int) -> bytes:
        """CMD23 SET_BLOCK_COUNT."""
        self.ep1_send(pack_cmd_A(EmmcSubOp.SET_BLOCK_COUNT, n))
        return self.ep1_recv(8)

    def stop_and_status(self) -> bytes:
        """CMD12 STOP + CMD13 SEND_STATUS."""
        self.ep1_send(pack_cmd_A(EmmcSubOp.STOP_AND_STATUS, 0))
        return self.ep1_recv(8)

    # ---- bulk read (USER/BOOT via CMD18) ----
    def bulk_read(self, count_sectors: int) -> bytes:
        """
        Format D bulk read: send the setup packet on EP1 OUT and receive
        the bulk data on EP1 IN. TODO: there may be a required prologue
        (SET_BLOCK_COUNT and/or an address-set command).
        """
        self.ep1_send(pack_bulk_read_setup(count_sectors))
        return self.ep1_recv(16 + count_sectors * 512)

    # ---- bulk write (USER/BOOT/RPMB) ----
    def bulk_write(self, opcode: int, count_sectors: int, block_addr: int, payload: bytes) -> int:
        """
        Format C bulk write: 16-byte setup on EP1 OUT followed by N×512
        bytes on EP2 OUT. For RPMB the payload must be a sequence of
        RPMB frames produced by build_rpmb_frame().
        """
        assert len(payload) == count_sectors * 512
        self.ep1_send(pack_bulk_write_setup(opcode, count_sectors, block_addr))
        return self.ep2_send(payload)


# ============================================================
# Sanity check (offline)
# ============================================================
if __name__ == "__main__":
    import sys

    print("== Packet structure sanity check (offline) ==")
    print(f"  cmd_A(SWITCH→RPMB)         = "
          f"{pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, PartAccess.RPMB)).hex()}")
    print(f"  cmd_A(SWITCH→USER restore) = "
          f"{pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)).hex()}")
    print(f"  cmd_A(SWITCH→HS200)        = "
          f"{pack_cmd_A(EmmcSubOp.SWITCH, make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)).hex()}")
    print(f"  cmd_B(read ECSD 512)       = "
          f"{pack_cmd_B(LongRecvSubOp.READ_BLOCK_512, 0x200, 0).hex()}")
    print(f"  bulk_read_setup(1 sector)  = "
          f"{pack_bulk_read_setup(1).hex()}")

    # Compare against the immediates we observed in Xgpro.exe.
    rpmb_arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.PARTITION_CONFIG, PartAccess.RPMB)
    assert rpmb_arg == 0x01B30300, f"RPMB switch arg mismatch: 0x{rpmb_arg:08x} vs 0x01B30300"
    user_arg = make_switch_arg(SwitchAccess.CLEAR_BITS, Ecsd.PARTITION_CONFIG, 0x07)
    assert user_arg == 0x02B30700, f"USER switch arg mismatch: 0x{user_arg:08x} vs 0x02B30700"
    hs200_arg = make_switch_arg(SwitchAccess.SET_BITS, Ecsd.HS_TIMING, 0x01)
    assert hs200_arg == 0x01AF0100, f"HS200 switch arg mismatch: 0x{hs200_arg:08x} vs 0x01AF0100"
    print("\n[OK] All three decoded commands match the bytes seen in Xgpro.exe.")

    # Optional device probe (requires a connected T48).
    if "--connect" in sys.argv:
        emmc = T48Emmc()
        try:
            emmc.connect()
            print("[OK] T48 detected")
        except Exception as e:
            print(f"[--] T48 not connected: {e}")
        finally:
            emmc.close()
