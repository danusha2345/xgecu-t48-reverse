# XGecu T48 — protocol reverse-engineering notes (eMMC focus)

> 🇷🇺 На русском: [PROTOCOL.ru.md](PROTOCOL.ru.md)

**Goal:** write a Linux-native program for reading/writing eMMC through
the XGecu T48 universal programmer in ISP (in-circuit) mode. This
document collects everything we recovered by static analysis of the
first-party software.

**Sources of truth:**

- `xgecu/Xgpro.exe` — first-party software (PE32, 32-bit x86, WinUSB).
- `xgecu/algorithm/*.alg` — FPGA bitstreams + algorithm parameters per
  chip family.
- `xgecu/InfoIC2Plus.dll` — chip database (dumped via the `dumpic`
  tool in [`minipro`](https://gitlab.com/DavidGriffith/minipro)).
- `minipro` 0.7.4 (GPL-3.0), file `src/t48.c` — the open-source
  reverse-engineered implementation of the T48 transport for
  classic-chip operations.

None of the proprietary files above are shipped in this repository.
The interested reader is expected to have a legitimate copy of `Xgpro`.

---

## 1. USB identity

From the bundled `xgecu/drv/Xgprowinusb.inf`:

- **VID/PID:** `0xA466 / 0x0A53`
- Class: WinUSB (vendor-specific bulk)
- DeviceInterfaceGUID: `{E7E8BA13-2A81-446E-A11E-72398FBDA82F}`
- Manufacturer: "Haikou Xingong Electronic Co,Ltd"

On Linux the device is opened directly through libusb
(`pyusb` / `libusb-1.0`); no kernel driver is required.

## 2. Endpoint map

From analysis of `Xgpro.exe` (call sites of `WinUsb_WritePipe` /
`WinUsb_ReadPipe`):

| EP   | Direction | Carries                       | Packet size                          |
|------|-----------|-------------------------------|--------------------------------------|
| EP1  | OUT / IN  | commands, config, status      | 8 or 16 bytes (fixed structures)     |
| EP2  | OUT       | bulk eMMC data (write side)   | `N × 512` bytes (sector-aligned)     |
| EP2  | IN        | not observed in Xgpro's flows |                                      |

Call-site counts in the binary: `WinUsb_WritePipe` = 36 distinct call
sites, `WinUsb_ReadPipe` = 70, `WinUsb_Initialize` = 1.

## 3. Classic-chip transport (already covered by `minipro`)

From `minipro/src/t48.c`. Opcodes `0x02..0x3F`:

```c
#define T48_NAND_INIT            0x02
#define T48_BEGIN_TRANS          0x03   // 64-byte init packet: protocol_id, voltages, clock, sizes
#define T48_END_TRANS            0x04
#define T48_READID               0x05
#define T48_READ_USER            0x06
#define T48_WRITE_USER           0x07
#define T48_READ_CFG             0x08
#define T48_WRITE_CFG            0x09
#define T48_WRITE_USER_DATA      0x0A
#define T48_READ_USER_DATA       0x0B
#define T48_WRITE_CODE           0x0C
#define T48_READ_CODE            0x0D
#define T48_ERASE                0x0E
#define T48_TEST_RAM             0x0F
#define T48_READ_DATA            0x10
#define T48_WRITE_DATA           0x11
#define T48_WRITE_LOCK           0x14
#define T48_READ_LOCK            0x15
#define T48_READ_CALIBRATION     0x16
#define T48_PROTECT_OFF          0x18
#define T48_PROTECT_ON           0x19
#define T48_SET_VCC_VOLTAGE      0x1B
#define T48_SET_VPP_VOLTAGE      0x1C
#define T48_READ_JEDEC           0x1D
#define T48_WRITE_JEDEC          0x1E
#define T48_LOGIC_IC_TEST_VECTOR 0x28
#define T48_RESET_PIN_DRIVERS    0x2D
#define T48_SET_VCC_PIN          0x2E
#define T48_SET_VPP_PIN          0x2F
#define T48_SET_GND_PIN          0x30
#define T48_SET_PULLUPS          0x31
#define T48_SET_PULLDOWNS        0x32
#define T48_MEASURE_VOLTAGES     0x33
#define T48_READ_PINS            0x35
#define T48_SET_OUT              0x36
#define T48_AUTODETECT           0x37
#define T48_UNLOCK_TSOP48        0x38
#define T48_REQUEST_STATUS       0x39
#define T48_BOOTLOADER_WRITE     0x3B
#define T48_BOOTLOADER_ERASE     0x3C
#define T48_SWITCH               0x3D
#define T48_RESET                0x3F
```

## 4. Protocol architecture: top-opcode + sub-opcode

The first byte of every EP1 command packet is the **top-opcode**. For
some top-opcodes the second byte is a **sub-opcode** that selects a
specific operation within that class.

```
EP1 command packet = [byte 0: top-opcode] [byte 1..7: sub-opcode/args]
```

### Top-opcodes — unified T48 table

| Top-opcode | Origin           | Purpose                                          | byte[1..7]                                       |
|------------|------------------|--------------------------------------------------|--------------------------------------------------|
| `0x02`     | minipro (classic)| `NAND_INIT`                                      | —                                                |
| `0x03`     | minipro (classic)| **`BEGIN_TRANSACTION`** (protocol_id, voltages, clock, sizes) | 64-byte packet                  |
| `0x04`     | minipro          | `END_TRANSACTION`                                | —                                                |
| `0x05`     | minipro + Xgpro  | `READID` — identify chip (used in eMMC init too) | 2-byte param, recv 32 bytes                      |
| `0x06`     | minipro + Xgpro  | `READ_USER` — config zone (recv 24 in eMMC init) | recv 24 bytes                                    |
| `0x07..0x1F` | minipro        | classic-chip operations                          | —                                                |
| `0x08`     | Xgpro NEW (eMMC) | **"long-recv" envelope**                         | sub-opcode (`0x48` = read 512 B) + length + addr |
| `0x14`     | Xgpro NEW (eMMC) | **bulk-write setup** before EP2 OUT              | sub-opcode + count + block_addr                  |
| `0x21`     | Xgpro NEW (eMMC) | init / algorithm select for eMMC                 | 1-byte parameter from settings                   |
| `0x27`     | Xgpro NEW (eMMC) | **eMMC sub-command dispatcher**                  | sub-opcode + 32-bit argument (see below)         |
| `0x39`     | minipro          | `REQUEST_STATUS`                                 | —                                                |
| `0x3F`     | minipro          | `RESET`                                          | —                                                |

### Sub-opcodes under top-opcode `0x27` (eMMC subcommands)

| Sub-op | Semantics                                          | arg32                                                     |
|--------|----------------------------------------------------|-----------------------------------------------------------|
| `0x46` | **CMD6 SWITCH**                                    | BE-encoded JEDEC: `[Access][Index][Value][CmdSet]`        |
| `0x4C` | **CMD12 STOP + CMD13 STATUS**                      | `0`                                                       |
| `0x4D` | commit / finalize FPGA (password / RPMB write)     | —                                                         |
| `0x50` | 512-byte data transfer (CMD24 / OTP / RPMB write)  | `0x200`                                                   |
| `0x57` | **CMD23 SET_BLOCK_COUNT**                          | block count (usually `1`)                                 |
| `0x5C` | TBD (1 call site)                                  | —                                                         |
| `0x5D` | Read WGP table (Write-Group Protection)            | —                                                         |

### Sub-opcode under top-opcode `0x08`

| Sub-op | Semantics                                                    |
|--------|--------------------------------------------------------------|
| `0x48` | **CMD8 SEND_EXT_CSD** / CMD17 READ_SINGLE_BLOCK (recv 512 B) |

The 7 sub-opcodes under `0x27` cluster above `0x40` — they are exactly
the part of the device protocol that `minipro` does *not* implement,
and they handle every eMMC operation that involves talking to the chip
controller (versus the FPGA itself).

## 5. eMMC init sequence

Reverse of function `0x4af370` in `Xgpro.exe` (the eMMC init sub-step
called after `BEGIN_TRANSACTION` from the caller):

```
Step 1: top-opcode 0x21 + 1-byte parameter [from 0x7485d0]    → recv 8 bytes
        (probably "select algorithm/variant" for eMMC)

Step 2: top-opcode 0x05 (READID) + 2-byte parameter [0x7a39cc] → recv 32 bytes
        (chip ID / OCR / CID)

Step 3: top-opcode 0x06 (READ_USER)                            → recv 24 bytes
        (config or CSD)

Step 4: top-opcode 0x27, sub 0x46 (CMD6 SetBits HS_TIMING=0x01)   → switch to HS-200
Step 5: top-opcode 0x27, sub 0x46 (CMD6 …)                        → another ECSD setup
```

The `BEGIN_TRANSACTION` (opcode `0x03`) with `protocol_id = 0x31`
(`IC2_ALG_EMMC`) and the right `variant` (e.g. `0x4100` for ISP 1-bit)
is sent *before* `0x4af370` from the calling function. The 64-byte
layout of the `BEGIN_TRANS` packet is documented in `minipro/src/t48.c`.

## 6. Packet formats

There are **four** distinct EP1 packet shapes used for eMMC operations,
plus the optional EP2 OUT bulk payload.

### Format A — 8-byte command via wrapper `0x492f30`

```c
struct EP1_Cmd_A {        // send + short recv
    uint8_t  top_opcode;  // = 0x27
    uint8_t  sub_opcode;  // 0x46/0x4C/0x4D/0x50/0x57/0x5C/0x5D
    uint16_t pad;         // = 0x0000
    uint32_t arg;         // 4-byte LE argument
};
```
**Use:** control commands (`CMD6 SWITCH`, `CMD13 STATUS`,
`CMD23 SET_BLOCK_COUNT`, commit/finalize, etc.)

### Format B — 8-byte command via wrapper `0x492900`

```c
struct EP1_Cmd_B {        // send + larger recv
    uint8_t  top_opcode;  // = 0x08
    uint8_t  sub_opcode;  // 0x48 = read 512-byte block
    uint16_t length;      // expected reply length (e.g. 0x0200 = 512)
    uint32_t arg;         // address / parameter
};
```
**Use:** requests with variable reply (CMD8 `SEND_EXT_CSD` reads 512
bytes via this path).

### Format C — bulk write via wrapper `0x492670`

```
EP1 OUT: 16-byte setup, top-opcode = 0x14
EP2 OUT: N × 512 bytes of payload (JEDEC RPMB frames or plain CMD25 blocks)
```
**Use:** `CMD25 WRITE_MULTIPLE_BLOCK`, RPMB writes.

### Format D — bulk read via wrapper `0x492590`

```c
struct EP1_BulkRead_Setup {       // 16 bytes
    uint32_t magic_and_op;        // = 0x02000015  (LE: bytes [15 00 00 02])
                                  // top-opcode 0x02, sub-byte 0x15(?)
    uint32_t reserved;            // = 0
    uint16_t count;               // number of 512-byte blocks
    uint16_t block_size;          // = 0x0200
    uint16_t padding;             // = 0
};
// → send 16 bytes on EP1 OUT (pipe 1)
// → recv (count * 512 + 16) bytes on EP1 IN (pipe 0x81): 16-byte header + bulk data
```
**Use:** `CMD18 READ_MULTIPLE_BLOCK`. Note that bulk read data comes
back on EP1 IN (not EP2 IN).

## 7. Key decoding: opcode `0x46` (CMD6 SWITCH)

The 32-bit `arg` for sub-opcode `0x46`, stored in little-endian by the
wrapper, **reads as the JEDEC eMMC CMD6 argument in big-endian**:

```
arg in LE memory       BE byte view             JEDEC CMD6 SWITCH argument
─────────────────      ─────────────────        ─────────────────────────────
                       [B3 B2 B1 B0]
                       Access | Index | Value | CmdSet
```

`Access` ∈ `{0x01 Set-Bits, 0x02 Clear-Bits, 0x03 Write-Byte}`,
`Index` ∈ ECSD field index (0–255), `Value` is the byte to write.

**Commands decoded from `Xgpro.exe`:**

| `arg` (LE) | BE bytes        | JEDEC ECSD field                                | Semantics                          |
|------------|-----------------|-------------------------------------------------|------------------------------------|
| `0x01B30300` | `01 B3 03 00` | `[179] PARTITION_CONFIG`, Set-Bits, Value `0x03`| **Switch to RPMB**                 |
| `0x02B30700` | `02 B3 07 00` | `[179] PARTITION_CONFIG`, Clear-Bits, Value `0x07` | **Switch back to USER**         |
| `0x01AF0100` | `01 AF 01 00` | `[175] HS_TIMING`, Set-Bits, Value `0x01`       | **Switch to HS-200** (init step)   |
| `0x02FFFF00` | `02 FF FF 00` | ?                                               | early-init reset (TBD)             |

So `CMD6 SWITCH` to any partition (BOOT1/BOOT2/RPMB/USER/GPP1–4) is
simply sending a Format A packet with `sub_opcode = 0x46` and an `arg`
that holds the BE-encoded JEDEC SWITCH argument.

`PARTITION_ACCESS` field (bits [2:0] of ECSD index 179):

| Value | Partition |
|-------|-----------|
| `0b000` | USER (default) |
| `0b001` | BOOT1 |
| `0b010` | BOOT2 |
| `0b011` | RPMB |
| `0b100..0b111` | GPP1..GPP4 |

## 8. Format C internals — bulk write (`0x492670` → EP2)

Inside `0x492670`, the 512-byte buffer that is sent on EP2 is built as
a **JEDEC-compatible RPMB frame**, with exact field offsets:

| Offset       | Size | Purpose                                                 | Matches JEDEC RPMB |
|--------------|------|---------------------------------------------------------|---------------------|
| `0x000..0x0C4` | 196 | Stuff bytes                                            | ✓ stuff bytes       |
| `0x0C4..0x0E4` | 32  | Key/MAC (selected from internal table `0x79A690` or `0x7C8048`) | ✓ Authentication Key / MAC |
| `0x0E4..0x1E4` | 256 | Data                                                   | ✓ Data              |
| `0x1E4..0x1F4` | 16  | Random Nonce (`rand()`, optional)                      | ✓ Nonce             |
| `0x1F4..0x1F8` | 4 BE | Write Counter                                         | ✓ Write Counter     |
| `0x1F8..0x1FA` | 2   | Address                                                | ✓ Address           |
| `0x1FA..0x1FC` | 2   | Block Count                                            | ✓ Block Count       |
| `0x1FC..0x1FE` | 2   | Result                                                 | ✓ Result            |
| `0x1FE..0x200` | 2   | Request / Response                                     | ✓ Request/Response  |

**Transmission sequence:**

1. EP1 OUT: 16-byte setup packet with top-opcode `0x14` (length `0x10`).
2. EP2 OUT (`WinUsb_WritePipe(pipe=2)`): N × 512 bytes = RPMB frames.

Flags `arg28 / arg2C` of the wrapper toggle nonce and key inclusion, so
the same function also serves plain `CMD25` writes (without the RPMB
key/MAC/nonce wrapping).

## 9. Format D — bulk read (`0x492590` → EP1 IN)

```c
// 16-byte setup, magic 0x02 / sub-byte 0x15:
struct EP1_BulkRead_Setup {
    uint32_t magic_and_op;  // = 0x02000015
    uint32_t reserved;      // = 0
    uint16_t count;         // number of 512-byte blocks
    uint16_t block_size;    // = 0x0200
    uint16_t padding;       // = 0
};
// → 16 bytes on EP1 OUT (pipe 1)
// → (count * 512 + 16) bytes on EP1 IN (pipe 0x81): 16-byte header + bulk data
```

Notable: EP2 IN does not appear to be used by Xgpro for eMMC. All bulk
reads come back through EP1 IN.

## 10. Low-level send/recv functions (confirmed by disassembly)

```c
// 0x4dc380 — sub_send(handle, buf, len)
//   → WinUsb_WritePipe(h, PipeID=1, buf, len, &transferred, NULL)
// EP1 OUT (pipe ID 1)

// 0x4dc300 — sub_recv(handle, buf, len)
//   → WinUsb_ReadPipe(h, PipeID=0x81, buf, len, &transferred, NULL)
// EP1 IN (pipe ID 0x81)
```

For bulk writes the wrapper calls `WinUsb_WritePipe` with `PipeID=2`
directly (EP2 OUT).

## 11. Wrapper hierarchy in `Xgpro.exe`

```
Layer 3 — semantic eMMC commands:
  0x4af370   eMMC init sub-step (calls 0x492f30 twice with sub-op 0x46)
  0x4acee0   CMD12 + CMD13 (sub-op 0x4C)
  0x4ad240   CMD13 alt path (sub-ops 0x57, 0x50)
  0x49d910   CMD18/25 BGA-socket path
  0x4a98f0   CMD18/25 ISP path (← our case! uses 0x492670)
  0x4a8110   bulk-read with watchdog

Layer 2 — USB-command builders:
  0x492f30   8-byte EP1 command, top-opcode 0x27 (Format A, 101 call sites)
  0x492670   bulk: 16-byte EP1 setup + N×512 on EP2 (Format C, RPMB-aware)
  0x492590   bulk-read: 16-byte EP1 setup + EP1 IN read (Format D)
  0x492900   8-byte EP1 command, top-opcode 0x08 (Format B, 0x48 = read 512 B)
  0x4dc070   composite EP1 transaction wrapper (10 WritePipe call sites)

Layer 1 — raw USB:
  0x4dc380   sub_send → WinUsb_WritePipe(EP1)
  0x4dc300   sub_recv → WinUsb_ReadPipe(EP1 IN)
  0x633e6c   stub for WinUsb_WritePipe (called with PipeID 1 or 2)
  0x633e66   stub for WinUsb_ReadPipe
```

## 12. JEDEC CMD → packet (decoded points)

| JEDEC CMD       | Function | Wrapper(s)             | top/sub-op | arg32                                                        |
|-----------------|----------|-------------------------|------------|--------------------------------------------------------------|
| init (CMD0/1/?) | 0x4af370 | `0x492f30`             | 0x27/0x46  | `0x02FFFF00` then `0x01AF0100` (two packets)                 |
| CMD12 + CMD13   | 0x4acee0 | `0x492f30`             | 0x27/0x4C  | `0`                                                          |
| CMD13 (alt)     | 0x4ad240 | `0x492f30`             | 0x27/0x57, 0x27/0x50 | `1`, then variable                                 |
| CMD8 EXT_CSD    | 0x4a1130 | `0x492900`             | 0x08/0x48  | length=`0x0200`, arg=`0`                                     |
| CMD18 ISP       | 0x4a98f0 | `0x492590` + `0x492670`| 0x02/0x15  | block_count                                                  |
| CMD25 ISP write | 0x4a98f0 | `0x492670`             | 0x14/…     | + EP2 OUT payload (RPMB frame layout)                        |
| init handshake  | 0x4af370 | raw `0x4dc380/0x4dc300`| 0x21, 0x05, 0x06 | recv 8/32/24 bytes respectively                        |

## 13. `.alg` algorithm-file format

The Xgpro algorithm files (`xgecu/algorithm/*.alg`) contain compressed
FPGA bitstreams. The format is fully reverse-engineered and the
`tools/extract_alg.py` script in this repository round-trips every
shipped `.alg` correctly.

```
0x000              char[]   algorithm-family name, ASCII, \0-terminated
                            (e.g. "EMMC211210", "EMMC18", "SPI-18", "AT45DB")
0x000..0x220       —        header padded with zeros (some families
                            keep sparse parameters here)
0x220              u32 LE   decompressed bitstream size = 340604
                            (constant for every shipped .alg — implies
                            a single FPGA, ≈ Xilinx Spartan-6 LX9 class)
0x224              u32 LE   CRC32 of the compressed data
                            = (zlib.crc32(comp) XOR 0xFFFFFFFF)
0x228..end         …        compressed bitstream, zero-RLE over 16-bit words:
                              read u16 val;
                              if val != 0: emit val
                              else:        read u16 len; emit `len` zero-words
```

The decompressed payload starts with the standard FPGA bitstream
preamble: 16 × `0xFF` dummy bytes followed by the sync word
`AA 99 55 66` (canonical Xilinx Spartan-6 sync).

### `variant` ↔ `.alg` file (via the high byte of `variant`)

The chip database (`InfoIC2Plus.dll`) stores per-chip `variant`s like
`0x5300`, `0x4100`, etc. The **high byte** of `variant` is the
algorithm number that gets substituted into the algorithm filename:

| `variant` high byte | Name pattern    | `.alg` file              | Mode                  |
|---------------------|-----------------|--------------------------|-----------------------|
| `0x53`              | `_8Bit @BGA153` | `EMMC_53_{18,33}.alg`    | BGA socket, 8-bit bus |
| `0x54`              | `_4Bit @BGA153` | `EMMC_54_{18,33}.alg`    | BGA socket, 4-bit bus |
| `0x51`              | `_1Bit @BGA153` | `EMMC_51_{18,33}.alg`    | BGA socket, 1-bit bus |
| `0x44`              | `(ISP) _4Bit`   | `EMMC_44_{18,33}.alg`    | **ISP 4-bit**         |
| `0x41`              | `(ISP) _1Bit`   | `EMMC_41_{18,33}.alg`    | **ISP 1-bit**         |

The `_18` / `_33` suffix is `VCCQ = 1.8 V` / `3.3 V`.

## 14. Chip database

`InfoIC2Plus.dll` ships with `Xgpro` and contains the per-chip
parameters consumed by `BEGIN_TRANSACTION`. The `dumpic/dump-infoic2plus-dll.c`
utility in `minipro` extracts it to JSON.

For the Xgpro version we examined, the database contains:

- 173 manufacturers, 34 352 chip entries in total.
- **4 796 eMMC entries** (chip type `7`), all with `protocol_id = 0x31`.

## 15. Buffer address map (from Xgpro UI strings)

```
BOOT1 last page : buffer 0x10000-0x13FFF (16 KB), device 0x1FC50000-0x1FC53FFF
BOOT2 last page : buffer 0x30000-0x33FFF (16 KB), device 0x1FC70000-0x1FC73FFF
```

The device-side addresses depend on the actual eMMC capacity; the
buffer-side addresses are what Xgpro uses internally.

## 16. Operation sketches (draft)

### Read EXT_CSD (512 bytes)

```
0. begin_transaction (top-op 0x03) with protocol_id = 0x31 and
   variant for the target chip (e.g. 0x4100 for ISP 1-bit)
1. eMMC init: CMD0 → CMD1 (OCR) → CMD2 (CID) → CMD3 → CMD7
   Implemented in Xgpro through a sequence of 0x21/0x05/0x06 raw
   commands + CMD6 SetBits HS_TIMING=1
2. EP1 cmd Format B: top-op=0x08, sub-op=0x48, length=0x200, arg=0
   → recv 512-byte EXT_CSD
```

### Read BOOT1 (16 KB)

```
1. CMD6 SWITCH: sub-op=0x46, arg = encode(SetBits, 0xB3=PARTITION_CONFIG, Value=0x01)
2. Iterate over blocks: EP1 cmd Format B with sub-op=0x48, length=0x200,
   arg=block_address, OR bulk-read via 0x492590
3. CMD6 SWITCH back: sub-op=0x46, arg = encode(ClearBits, 0xB3, 0x07)
```

### Read USER area (bulk read via ISP)

```
1. CMD18 setup via 0x492590 (16-byte EP1 OUT setup) with N = block count
2. Receive N × 512 bytes on EP1 IN (with 16-byte response header)
3. Optionally CMD12 STOP (sub-op 0x4C)
```

## 17. Open questions

- [ ] Exact semantics of every sub-opcode (USB capture will validate
      the proposed mapping).
- [ ] Final word on the 16-byte setup-packet payload for Format D
      (the `0x02000015` magic is confirmed; the trailing fields are
      inferred).
- [ ] Reply framing on EP1 — observed reply sizes are 8 / 24 / 32 /
      `count*512+16`; the field layouts are not yet decoded.
- [ ] How Xgpro learns the FPGA is ready to deliver bulk data on EP1
      IN after `CMD18` (the trigger / handshake).
- [ ] Adapter-authentication pass-through: if the PC software ever
      relays the auth bytes between the genuine eMMC-ISP adapter and
      the T48 firmware (we expect not — see §18).
- [ ] Full opcode table in the `0x40..0x60` range (there may be unused
      sub-opcodes that Xgpro doesn't exercise for eMMC).

## 18. The crypto-equipped eMMC-ISP adapter

The genuine **"XGecu EMMC-ISP VER 1.00"** adapter contains a secure
authentication IC (likely an Atmel/Microchip ATSHA204A or similar).
Per the manufacturer's product page the chip is anti-clone protection;
the adapter "cannot be DIY" and is locked to the T48 model only (not
the older TL866 family, and not the T56).

The relevant fact for this project: the adapter **authenticates to the
T48's firmware**, not to the PC software. Our PC code therefore does
not need to break the crypto — it just issues the documented USB
commands, and the T48 firmware itself runs the challenge/response with
the adapter using a key shared between them (likely sealed inside both
parts of the system).

If a future USB capture turns out to show the PC relaying auth bytes,
that would be plain pass-through (no key knowledge needed on the host).

---

## Status checklist

✅ minipro 0.7.4 built and confirmed to run<br>
✅ Chip database dumped (4 796 eMMC entries)<br>
✅ `.alg` format fully reverse-engineered and verified (unpacker
round-trips every file)<br>
✅ USB identity, endpoint map, wrapper hierarchy established<br>
✅ Format A 8-byte EP1 packet documented<br>
✅ eMMC sub-opcode list extracted, 6 of 7 mapped to JEDEC semantics<br>
✅ CMD6 SWITCH argument encoding fully decoded<br>
✅ RPMB frame layout (Format C internals) fully decoded<br>
⏳ Final byte-level validation of every opcode (needs a USB capture
   from a real T48)<br>
⏳ The 16-byte setup payload for Format D (inferred, not yet directly
   verified)<br>
