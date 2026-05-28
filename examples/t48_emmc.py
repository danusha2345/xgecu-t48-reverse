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
    # Classic (from minipro/src/t48.c) — also used by Xgpro for eMMC
    NAND_INIT       = 0x02
    BEGIN_TRANS     = 0x03    # 64-byte init+pin-check packet for eMMC too
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
# T48 voltage tables (recovered from minipro/src/t48.c)
# These are the *actual* voltages corresponding to indices 0..63
# used in SET_VCC_VOLTAGE / SET_VPP_VOLTAGE / SET_VCCIO_VOLTAGE.
# ============================================================

# 64-step VCC table — feeds the on-board VCC DAC.
VCC_MAP = (
    0.00, 1.74, 1.83, 1.89, 2.00, 2.07, 2.18, 2.23,
    2.32, 2.41, 2.45, 2.56, 2.65, 2.73, 2.79, 2.90,
    3.02, 3.08, 3.16, 3.28, 3.33, 3.42, 3.48, 3.57,
    3.65, 3.75, 3.84, 3.89, 3.97, 4.08, 4.16, 4.23,
    4.31, 4.40, 4.48, 4.55, 4.65, 4.71, 4.80, 4.88,
    4.97, 5.05, 5.14, 5.18, 5.29, 5.37, 5.45, 5.54,
    5.64, 5.76, 5.81, 5.91, 5.99, 6.06, 6.18, 6.23,
    6.33, 6.37, 6.45, 6.54, 6.62, 6.72, 6.80, 6.86,
)
# 64-step VPP table — programming voltage for UV-EPROM-style chips.
VPP_MAP = (
     9.31,  9.56,  9.83, 10.11, 10.32, 10.60, 10.87, 11.14,
    11.32, 11.61, 11.86, 12.15, 12.35, 12.63, 12.90, 13.18,
    13.35, 13.62, 13.88, 14.16, 14.38, 14.66, 14.92, 15.19,
    15.39, 15.65, 15.93, 16.19, 16.43, 16.70, 16.95, 17.23,
    17.22, 17.48, 17.76, 18.04, 18.26, 18.53, 18.80, 19.07,
    19.25, 19.52, 19.80, 20.07, 20.30, 20.56, 20.85, 21.10,
    21.27, 21.56, 21.82, 22.10, 22.31, 22.59, 22.86, 23.13,
    23.32, 23.58, 23.86, 24.13, 24.37, 24.63, 24.90, 25.16,
)
# 5-step VCCIO table (used only for classic chips' IO; eMMC uses
# variant-encoded VCCQ instead — see PROTOCOL.md §20.3).
VCCIO_MAP = (2.35, 2.47, 2.93, 3.23, 3.45)


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

    # ---- voltage commands (classic-chip API; for eMMC voltages are
    #      baked into BEGIN_TRANSACTION via the chip's variant field) ----
    def set_vcc_voltage(self, vcc_index: int) -> None:
        """SET_VCC (opcode 0x1B / SET_VCC_PIN sub-form, minipro-style).
        Pkt: msg[0]=0x2E, msg[0x10]=j1vcc, msg[0x16]=vcc_index (1..63),
        sends 48 bytes EP1 OUT. See minipro src/t48.c.
        Index → real volts: VCC_MAP[vcc_index]."""
        assert 0 <= vcc_index < 64
        msg = bytearray(48)
        msg[0] = 0x2E                       # T48_SET_VCC_PIN
        msg[0x16] = vcc_index               # voltage index
        self.ep1_send(bytes(msg))

    def set_vpp_voltage(self, vpp_index: int) -> None:
        """SET_VPP_PIN sub-cmd 1 — programming voltage (UV-EPROM etc.)."""
        assert 0 <= vpp_index < 64
        msg = bytearray(48)
        msg[0] = 0x2F                       # T48_SET_VPP_PIN
        msg[1] = 1                          # sub-cmd: set VPP voltage
        msg[8] = vpp_index
        self.ep1_send(bytes(msg))

    def set_vccio_voltage(self, vccio_index: int) -> None:
        """SET_VPP_PIN sub-cmd 2 — IO voltage for classic chips (5 steps)."""
        assert 0 <= vccio_index < 5
        msg = bytearray(48)
        msg[0] = 0x2F                       # T48_SET_VPP_PIN
        msg[1] = 2                          # sub-cmd: set VCCIO voltage
        msg[8] = vccio_index
        self.ep1_send(bytes(msg))

    def measure_voltages(self) -> dict:
        """MEASURE_VOLTAGES (top-op 0x33) — read back live rail voltages.
        Mirrors minipro t48_measure_voltages. Returns dict with keys
        'vpp', 'vusb', 'vcc', 'vccio' (volts, float)."""
        msg = bytearray(16)
        msg[0] = 0x33
        self.ep1_send(bytes(msg))
        reply = self.ep1_recv(24)
        u16 = lambda o: reply[o] | (reply[o+1] << 8)
        return {
            'vpp':   u16(8)  * 0x0F78  / 0x1000 / 100.0,
            'vusb':  u16(12) * 0xCCF6  / 0x27000 / 100.0,
            'vcc':  (u16(16) * 0xB32E  / 0x27000 - 0x14) / 100.0,
            'vccio': u16(20) * 0x0294  / 0x1000 / 100.0,
        }

    # ---- session start: BEGIN_TRANSACTION + pin check + OVC check ----
    def begin_transaction(self, packet64: bytes) -> bytes:
        """
        Send the 64-byte BEGIN_TRANSACTION setup packet on EP1 OUT.
        Caller is responsible for building the packet from the chip-DB
        parameters that Xgpro stores in DAT_007a39xx globals (loaded in
        Xgpro by FUN_004edaa0 when a chip is selected).

        Packet layout (recovered from FUN_00444bc0):
            byte 0     : 0x03  (top-opcode BEGIN_TRANS)
            byte 1     : protocol_id (0x31 for eMMC)
            byte 2     : variant low byte  (= chip_db.variant & 0xFF)
            byte 3     : icsp / extra flags  (DAT_007a3ba6)
            byte 4..6  : data_memory_size (LE)
            byte 6     : pin_map / chip_info (= DAT_007a39b4)
            byte 7     : DAT_007a397b (extra flags byte)
            byte 8..10 : DAT_007a39ac (ushort)
            byte 10..12: DAT_007a39c0 (ushort)
            byte 12..14: DAT_007a39c4 (ushort)
            byte 14..16: DAT_007a39b0 (ushort)
            byte 16..20: code_memory_size (LE)
            byte 20..24: encoded voltages
            ... 64 bytes total, remaining mostly chip-specific
        """
        assert len(packet64) == 64
        self.ep1_send(packet64)
        # No immediate reply; status is fetched via REQUEST_STATUS afterwards.
        return b''

    def request_status(self) -> bytes:
        """
        Send REQUEST_STATUS (top-opcode 0x39) and receive 32-byte reply.

        Reply layout (Ghidra-verified in FUN_00444bc0, line 188+ and
        matches minipro's t48_get_ovc_status):
            byte 0     : error code
            byte 2..4  : c1 counter (LE u16)
            byte 4..6  : c2 counter (LE u16)
            byte 8..12 : verify-write address (LE u32)
            byte 12    : OVC status (bit 0 = overcurrent)
        """
        pkt = struct.pack('<BB6x', 0x39, 0)
        self.ep1_send(pkt)
        return self.ep1_recv(0x20)

    def check_ovc(self) -> bool:
        """
        Returns True if the overcurrent protection has tripped.
        Convention follows Xgpro's check `(reply[12] & 1) != 0` after
        sending BEGIN_TRANSACTION.
        """
        reply = self.request_status()
        return (reply[12] & 0x01) != 0

    def end_transaction(self, error_flag: int = 0) -> None:
        """
        Send END_TRANSACTION (top-opcode 0x04) to release the session.
        Xgpro sends byte 1 = 0x01 when terminating due to an OVC event.
        """
        self.ep1_send(struct.pack('<BB6x', 0x04, error_flag & 0xFF))

    def begin_session_with_ovc_check(self, packet64: bytes) -> dict:
        """
        Convenience wrapper used by Xgpro's pin_detect_pass routine
        (FUN_00444bc0): BEGIN_TRANS → REQUEST_STATUS → if OVC then
        END_TRANS(1) and report error.

        Returns {'ovc': bool, 'status': raw 32-byte reply,
                 'success': bool}.
        """
        self.begin_transaction(packet64)
        status = self.request_status()
        ovc = (status[12] & 0x01) != 0
        if ovc:
            self.end_transaction(error_flag=0x01)
        return {'ovc': ovc, 'status': status, 'success': not ovc}

    # ---- init (no BEGIN_TRANSACTION needed for eMMC!) ----
    def init_emmc(self, algo_param: int, readid_param: int = 0) -> dict:
        """
        eMMC chip-level init: opcode 0x21 → 0x05 → 0x06.

        IMPORTANT (revised after deeper Ghidra reverse): this is the
        eMMC chip-side initialization (CMD0/1/2/3 sequence). It runs
        AFTER begin_session_with_ovc_check() has done the programmer-side
        BEGIN_TRANSACTION (top-op 0x03, 64 bytes) and pin/OVC check.

        Returns a dict with parsed OCR / CID / CSD bytes.

        :param algo_param: 1-byte algorithm/variant selector
                           (= DAT_007485d0, set by Xgpro from chip variant)
        :param readid_param: 2-byte parameter for opcode 0x05 (= DAT_007a39cc)
        """
        # Step 1 — opcode 0x21 + 1-byte param → recv 8 B (status + OCR)
        self.ep1_send(struct.pack('<BB6x', 0x21, algo_param & 0xFF))
        r1 = self.ep1_recv(8)
        ocr = struct.unpack_from('<I', r1, 4)[0] if r1[1] == 0 else None

        # Step 2 — opcode 0x05 + u16 param → recv 32 B (status + CID)
        self.ep1_send(struct.pack('<BBHI', 0x05, 0, readid_param & 0xFFFF, 0))
        r2 = self.ep1_recv(0x20)
        cid = bytes(r2[8:0x18]) if r2[1] == 0 else None

        # Step 3 — opcode 0x06 → recv 24 B (status + CSD)
        self.ep1_send(struct.pack('<BB6x', 0x06, 0))
        r3 = self.ep1_recv(0x18)
        csd = bytes(r3[8:0x18]) if r3[1] == 0 else None

        return {'ocr': ocr, 'cid': cid, 'csd': csd,
                'replies': (r1, r2, r3)}

    def set_pipe_timeout(self, timeout_ms: int) -> None:
        """
        Call WinUsb_SetPipePolicy equivalent — sets PIPE_TRANSFER_TIMEOUT on
        IN pipes 0x81/0x82/0x83. pyusb doesn't expose this directly; on Linux
        the read() timeout argument plays the same role per-call.
        """
        self.read_timeout_ms = timeout_ms

    # ---- bulk read (USER/BOOT via CMD18) ----
    def bulk_read(self, count_sectors: int) -> bytes:
        """
        Format D bulk read for eMMC: send setup on EP1 OUT, receive bulk
        data on EP2 IN (Ghidra-verified in 0x4dbd50 — for chip_type==7).
        Total received size = count*512 + 16 (16-byte trailing header).
        TODO: there may be a required prologue (CMD23 SET_BLOCK_COUNT,
        address-set, etc.) — confirm with a USB capture.
        """
        self.ep1_send(pack_bulk_read_setup(count_sectors))
        return self.ep2_recv(16 + count_sectors * 512)

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
