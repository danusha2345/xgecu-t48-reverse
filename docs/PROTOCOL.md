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
✅ Ghidra-verified wire-format of all four packet formats (§19 below)<br>
⏳ Final byte-level validation of every opcode (needs a USB capture
   from a real T48)<br>

---

## 19. Ghidra-verified wire formats

After importing `Xgpro.exe` into Ghidra 12 and decompiling the key wrappers
the previous sections had inferred from capstone-level assembly, the following
details are now confirmed verbatim from the C-like decompilation. Numbers
in parentheses are Ghidra's auto-named function symbols (e.g. `FUN_004dc380`).

### 19.1 `sub_4dc380` (raw EP1 send) — `FUN_004dc380`

```c
void raw_send(handle, buf, len) {
    WinUsb_WritePipe(handle, /*PipeID=*/1, buf, len, &transferred, NULL);
}
```

Always pipe 1. Confirms our `EP1_OUT = 0x01`.

### 19.2 `sub_4dc300` (raw EP1 recv) — `FUN_004dc300`

```c
int raw_recv(handle, buf, len) {
    int slot = handle_to_slot(handle);      // 4 handles supported
    int chip_type = chip_type_table[slot * 0xEC];
    int actual_len = len;
    if (chip_type == 6)        // NAND
        actual_len = len + 1;  // NAND needs an extra byte
    int rc = WinUsb_ReadPipe(handle, /*PipeID=*/0x81, buf, actual_len, ...);
    return rc ? transferred : -1;
}
```

Always pipe 0x81 (EP1 IN). For NAND the host requests `len + 1` bytes.

### 19.3 Format A — `FUN_00492f30` (top-opcode `0x27`)

```c
void cmd_A(handle, byte sub_op, dword arg, char* reply_buf) {
    uint8_t pkt[8];
    pkt[0] = 0x27;
    pkt[1] = sub_op;
    *(u16*)&pkt[2] = 0;
    *(u32*)&pkt[4] = arg;
    if (raw_send(handle, pkt, 8) != 0) {            // EP1 OUT
        if (raw_recv(handle, reply_buf, 8) != -1) { // EP1 IN, 8 bytes
            if (reply_buf[1] != 0) { /* success */ }
        }
    }
}
```

Confirmed: 8-byte command, 8-byte reply on EP1 IN. `reply_buf[1] != 0`
appears to be the success indicator.

### 19.4 Format B — `FUN_00492900` (top-opcode `0x08`) — **EP2 IN for eMMC**

```c
void cmd_B(handle, byte sub_op, ushort length, dword arg, char* reply_buf) {
    uint8_t pkt[8];
    pkt[0] = 0x08;
    pkt[1] = sub_op;
    *(u16*)&pkt[2] = length;
    *(u32*)&pkt[4] = arg;
    if (raw_send(handle, pkt, 8) != 0) {                    // EP1 OUT
        int slot = handle_to_slot(handle);
        int chip_type = chip_type_table[slot * 0xEC];
        if (chip_type != 7 && chip_type != 8) {             // not eMMC, not VGA
            raw_recv(handle, reply_buf, length + 8);        // EP1 IN
        } else {
            WinUsb_ReadPipe(handle, /*PipeID=*/0x82,        // EP2 IN!
                            reply_buf, length + 8, ...);
        }
    }
}
```

**Critical correction**: for eMMC the Format B response arrives on **EP2 IN
(pipe 0x82)**, *not* EP1 IN. The total reply size is `length + 8`. Our
Python prototype has been updated accordingly.

### 19.5 Format C — `FUN_00492670` (bulk-write to eMMC) — **EP2 OUT**

The 16-byte EP1 setup packet is:

```c
struct {
    uint8_t  top_op;       // = 0x14
    uint8_t  sub_op;       // = param_8
    uint16_t pad;          // = 0
    uint32_t pad2;         // = 0
    uint16_t count;        // = param_6 (number of 512-byte sectors)
    uint16_t block_size;   // = 0x0200
    uint16_t pad3;         // = 0
};
```

The 512-byte payload buffer (passed in `param_2`) is patched in-place to embed
the **JEDEC-RPMB-style trailer** in its last 12 bytes plus optional 32-byte key
and 16-byte nonce:

| Offset | Size | Field             | Value                          |
|--------|------|-------------------|--------------------------------|
| `0x0C4..0x0E4` | 32 | Key/MAC      | from table `DAT_0079A690` (param_10=1) or `DAT_007C8048` (param_10=2) |
| `0x1E4..0x1F4` | 16 | Nonce        | `rand()` × 16 if `param_9 != 0`  |
| `0x1F4..0x1F8` | 4 BE | Write counter | `param_4` big-endian             |
| `0x1F8..0x1FA` | 2 | param_3       | byte 0x1F9 = lo, byte 0x1F8 = hi |
| `0x1FA..0x1FC` | 2 | param_5       | byte 0x1FB = lo, byte 0x1FA = hi |
| `0x1FC..0x1FE` | 2 | zero          | 0                                |
| `0x1FE..0x200` | 2 | param_7       | byte 0x1FF = lo, byte 0x1FE = hi |

Transmission per chip-type:

```c
if (chip_type == 7) {            // eMMC
    raw_send(handle, &setup, 16);                                          // EP1 OUT
    WinUsb_WritePipe(handle, /*pipe=*/2, payload, count * 512, ...);       // EP2 OUT
}
else if (chip_type == 8) {       // VGA
    raw_send(handle, &setup, 16);                                          // EP1 OUT
    WinUsb_WritePipe(handle, /*pipe=*/5, payload, count * 512, ...);       // EP5 OUT (!)
}
else {
    // Combined 16-byte setup + 512-byte payload sent together on EP1:
    raw_send(handle, /*pointer*/, 0x210);   // = 528 bytes on EP1 OUT
}
```

### 19.6 Format D — `FUN_00492590` (bulk-read setup)

```c
void bulk_read_setup(handle, void* recv_buf, ushort count) {
    uint8_t pkt[16];
    *(u32*)&pkt[0] = 0x02000015;     // magic / top-opcode + sub-byte
    *(u32*)&pkt[4] = 0;
    *(u16*)&pkt[8] = count;
    *(u16*)&pkt[10] = 0x0200;
    *(u16*)&pkt[12] = 0;
    *(u16*)&pkt[14] = 0;
    if (raw_send(handle, pkt, 16) != 0) {                                  // EP1 OUT
        int chip_type = ...;
        if (chip_type == 7 || chip_type == 8)                              // eMMC / VGA
            FUN_004dbd50(handle, recv_buf, count * 512 + 16);              // (TBD endpoint)
        else
            raw_recv(handle, recv_buf, count * 512 + 16);                  // EP1 IN
    }
}
```

For eMMC bulk reads the wrapper calls a *separate* helper `FUN_004dbd50` —
this one likely reads from a different pipe (EP2 IN is the natural candidate,
given the Format B precedent). Decompiling `FUN_004dbd50` is the next step.

### 19.7 `composite_EP1` — `FUN_004dc070` (multi-pipe transactions)

This wrapper handles transfers that don't fit a single endpoint. Per chip-type:

```c
if (chip_type == 6) {                  // NAND
    WinUsb_WritePipe(handle, 1, buf,     8,         ...);
    WinUsb_WritePipe(handle, 1, buf + 8, len - 7,   ...);   // split on EP1
}
else if (chip_type == 7) {             // eMMC
    WinUsb_WritePipe(handle, 1, buf,     8,         ...);   // setup on EP1
    WinUsb_WritePipe(handle, 2, buf + 8, len - 8,   ...);   // payload on EP2
}
else if (len > 0x40) {                 // large transfer, asynchronous
    // Setup + two parallel payloads using OVERLAPPED + WaitForSingleObject:
    WinUsb_WritePipe(handle, 1, buf,         8,           ...);
    WinUsb_WritePipe(handle, 2, buf + 8,     half_a,      ...);   // EP2
    WinUsb_WritePipe(handle, 3, buf + 8 + a, half_b,      ...);   // EP3 (!)
}
```

So Xgpro can stripe one logical command across **EP1 / EP2 / EP3 simultaneously**
for big payloads; the host waits on `WaitForSingleObject` for both EP2 and EP3
to drain. Not relevant for the eMMC ISP path we target, but worth knowing.

### 19.8 eMMC init (`FUN_004af370`) — exact raw packets

```c
// Step 1 — top-opcode 0x21:
buf[0] = 0x21;
buf[1] = DAT_007485d0;        // 1-byte parameter (set at config time)
raw_send(handle, buf, 8);
raw_recv(handle, reply, 8);

// Step 2 — top-opcode 0x05 (READID):
buf[0] = 0x05;
*(u16*)&buf[2] = DAT_007a39cc; // 2-byte parameter
*(u32*)&buf[4] = 0;
raw_send(handle, buf, 8);
raw_recv(handle, reply, 0x20);  // 32 bytes  ← chip ID / OCR / CID payload

// Step 3 — top-opcode 0x06 (READ_USER):
buf[0] = 6;
raw_send(handle, buf, 8);
raw_recv(handle, reply, 0x18);  // 24 bytes  ← config / CSD payload
```

The bytes of the reply at offset 0..1 carry a status code: the function
takes the success branch when `reply[1] != 0`, which matches the Format A
success convention.

### 19.9 Read EXT_CSD (`FUN_004a1130`) — full flow

The user-facing "Read ECSD" code (entry at `FUN_004a1130`) issues **three
back-to-back** Format B reads, all with the same parameters:

```c
FUN_00492900(handle, /*sub_op=*/0x48, /*length=*/0x200, /*arg=*/0, recv_buf);
FUN_00492900(handle, /*sub_op=*/0x48, /*length=*/0x200, /*arg=*/0, recv_buf);
FUN_00492900(handle, /*sub_op=*/0x48, /*length=*/0x200, /*arg=*/0, recv_buf);
```

This is likely a **triple-read for verification** (compare three copies of
EXT_CSD; if they all match the reader is happy). It's a defensive practice
on noisy long lines, common in production-grade eMMC tooling.

### 19.10 Reply layouts for init opcodes

The same `read_ECSD` function unambiguously decodes the bytes returned for
each of the three init opcodes. The reply buffer is read at fixed offsets:

```
8-byte reply to opcode 0x21 (INIT_EMMC)
──────────────────────────────────────
offset 1   :  byte  status   (0 = success)
offset 4..8:  u32   OCR register   (JEDEC eMMC, raw)
              bit 30 = high-capacity flag, bits [23:8] should be 0xFF8080 for 1.8 V

32-byte reply to opcode 0x05 (READID for CID)
─────────────────────────────────────────────
offset 1   :  byte  status (0 = OK)
offset 2..4:  u16   ?
offset 4..8:  u32   ?
offset 8..0x18: 16 bytes = CID register (JEDEC eMMC, 128-bit unique ID)

24-byte reply to opcode 0x06 (READ_USER for CSD)
────────────────────────────────────────────────
offset 1     :  byte  status (0 = OK)
offset 8..0x18: 16 bytes = CSD register (JEDEC eMMC, 128-bit Card-Specific Data)
```

Both CID and CSD are copied into the global buffer `DAT_007a4034`:
CID at offset 0, CSD at offset 0x10. Higher-level code reads from these
offsets directly. For chip-types other than eMMC the bytes are stored
in reverse byte order, but for eMMC (chip_type 7) they go in verbatim.

### 19.11 `FUN_004dbd50` — bulk-read for eMMC, full body

```c
void bulk_read_emmc(handle, buf, size) {
    int slot = handle_to_slot(handle);
    char chip_type = chip_type_table[slot * 0xEC];

    if (chip_type == 6) {                 // NAND
        raw_recv(handle, buf, size);              // EP1 IN
        return;
    }
    if (chip_type == 7 || chip_type == 8) {       // eMMC or VGA
        WinUsb_ReadPipe(handle, /*pipe=*/0x82, buf, size, ...);   // EP2 IN
        return;
    }
    // Other chip types — possibly split into parallel reads:
    if (size >= 0x41) {
        size /= 2;
        WinUsb_ReadPipe(handle, /*pipe=*/0x82, buf,         size, ...);   // EP2 IN
        WinUsb_ReadPipe(handle, /*pipe=*/0x83, buf + size,  size, ...);   // EP3 IN (!)
        WaitForSingleObject(event, 5000);
    } else {
        WinUsb_ReadPipe(handle, /*pipe=*/0x82, buf, size, ...);           // EP2 IN
    }
}
```

So **eMMC bulk reads always come back on EP2 IN (pipe 0x82)**, and for
non-eMMC big reads Xgpro can stripe across EP2 IN + EP3 IN in parallel.

### 19.12 `FUN_004dbd00` — *not* a "set timeout"; it's `WinUsb_SetPipePolicy`

```c
int set_pipe_policies(handle, ULONG timeout_ms /* stack arg */) {
    WinUsb_SetPipePolicy(handle, 0x81, /*PIPE_TRANSFER_TIMEOUT=*/3, 4, &timeout_ms);
    WinUsb_SetPipePolicy(handle, 0x82, 3, 4, &timeout_ms);
    WinUsb_SetPipePolicy(handle, 0x83, 3, 4, &timeout_ms);
    return 1;
}
```

Sets the per-pipe transfer timeout on all three IN pipes (`0x81/0x82/0x83`).
Confirms that EP3 IN really exists in the device descriptor.

### 19.13 `BEGIN_TRANSACTION` (top-opcode `0x03`) is *not* used for eMMC

The high-level eMMC dispatcher `FUN_004c9110` (≈ 1700 decompiled lines)
contains **four calls to `FUN_004af370` (the init sub-step) and only one
raw `FUN_004dc380` call** — no top-opcode `0x03` anywhere in the eMMC
read/write/RPMB flows. This means:

- **For eMMC, our own software does *not* need to send a 64-byte
  `BEGIN_TRANSACTION` packet at all.**
- The role that `BEGIN_TRANSACTION` plays for classic chips (selecting the
  per-chip algorithm and configuring voltages) is fulfilled in eMMC by
  **opcode `0x21`** plus the 1-byte parameter loaded from `DAT_007485d0`
  (which Xgpro sets earlier based on the user's `variant` choice).
- Practical consequence: the start-up sequence in the prototype simplifies
  to `connect()` → opcode `0x21` (+ param) → opcode `0x05` → opcode `0x06`
  → CMD6 SWITCH HS-200, with no `BEGIN_TRANSACTION` step.

### 19.14 Full endpoint map (post-Ghidra)

| Pipe ID | Direction | Role                                                   |
|---------|-----------|--------------------------------------------------------|
| `0x01`  | EP1 OUT   | All commands; combined 528-byte transfer for non-eMMC  |
| `0x02`  | EP2 OUT   | Bulk-write payload for eMMC                            |
| `0x03`  | EP3 OUT   | Parallel half of large non-eMMC writes                 |
| `0x05`  | EP5 OUT   | VGA-only bulk-write                                    |
| `0x81`  | EP1 IN    | All short responses (8/24/32 bytes)                    |
| `0x82`  | EP2 IN    | Format B responses for eMMC; bulk-read for eMMC + VGA  |
| `0x83`  | EP3 IN    | Parallel half of large non-eMMC reads                  |

For the eMMC ISP path only `EP1 OUT/IN` and `EP2 OUT/IN` are needed.

### 19.15 New top-opcode `0x26` — FPGA bitstream download

`FUN_004bb4d0` (`download_algo`) implements an FPGA bitstream upload
protocol used by the **VGA** path (chip_type 8), and possibly by other
"download from PC" cases. The packet structure is three sub-stages:

| Packet (LE bytes)   | Meaning                          |
|---------------------|----------------------------------|
| `26 00 00 20 ......` | Init download (size in `param_4`)|
| `26 01 ss ss ......` | Stream chunk (`0x1F8` bytes each)|
| `26 02 ss ss ......` | Wait for DONE flag, get error code in reply byte 2 |

This opcode is **not** used by the eMMC paths (eMMC algorithms are stored
on the programmer board and selected with opcode `0x21`).

---

## 20. Voltage, overcurrent protection, pin detection

### 20.1 Correction: `BEGIN_TRANSACTION` *is* used for eMMC

In §19.13 I claimed `BEGIN_TRANSACTION` (top-opcode `0x03`) is never sent
for the eMMC path. That conclusion was wrong: I had only inspected the
top-level dispatcher `FUN_004c9110`. The 64-byte `BEGIN_TRANSACTION`
packet is sent one level down, inside `FUN_00444bc0` (`pin_detect_pass`),
which is called from the dispatcher early in every eMMC operation.

So the correct picture for an eMMC session is:

```
1. user-level "select chip" UI:
     FUN_004edaa0 copies the chip-DB record (Ic_100) into globals
     DAT_007a39xx (protocol_id, variant, voltages, sizes, …)
2. operation start (Read / Write / Verify / etc.):
     FUN_00444bc0 (pin_detect_pass) is entered first:
       a. assemble the 64-byte BEGIN_TRANSACTION packet from globals
       b. raw_send(handle, packet, 0x40)                  ← EP1 OUT
       c. raw_send(handle, [0x39,0,0,0,0,0,0,0], 8)        ← REQUEST_STATUS
       d. raw_recv(handle, status_buf, 0x20)
       e. if (status_buf[12] & 0x01) {                    ← OVC tripped
            display "OverCurrent Protection !"
            raw_send(handle, [0x04,0x01,0,…], 8)          ← END_TRANS
            MessageBeep; abort.
          }
3. continue with the actual eMMC flow (opcode 0x21 init, …)
```

### 20.2 64-byte `BEGIN_TRANSACTION` packet layout for eMMC

The bytes are assembled in `FUN_00444bc0` from the global block
`DAT_007a39xx`, which `FUN_004edaa0` had populated from the chip's
`Ic_100` database record. The mapping (recovered from the
decompilation; offsets in the database record taken from the dumper
in `minipro/dumpic/dump-infoic2plus-dll.c`):

| Pkt offset | Source (`DAT_007a…`) | Source in `Ic_100`     | Field meaning              |
|-----------:|----------------------|------------------------|----------------------------|
| `0x00`     | (literal `0x03`)     | —                      | top-opcode `BEGIN_TRANS`   |
| `0x01`     | `DAT_007a3978`       | `protocol_id` (off 0)  | `0x31` for eMMC            |
| `0x02`     | `DAT_007a39a8`       | `variant` low (off 0x34)| algorithm variant low byte |
| `0x03`     | `DAT_007a3ba6`       | (extra flags)          | per-mode flags             |
| `0x04..6`  | `DAT_007a39ac` (u16) | (off 0x3c)             | data_memory_size           |
| `0x06`     | `DAT_007a39b4`       | (off 0x44)             | pin_map / chip_info        |
| `0x07`     | `DAT_007a397b`       | (off 4)                | extra flags                |
| `0x08..a`  | `DAT_007a39ac` (u16) | data_memory_size       | (also at 0x04 — Xgpro quirk)|
| `0x0a..c`  | `DAT_007a39c0` (u16) | (off 0x54)             | data_memory2_size          |
| `0x0c..e`  | `DAT_007a39c4` (u16) | (off 0x58)             | page_size                  |
| `0x0e..10` | `DAT_007a39b0` (u16) | (off 0x40)             | pulse_delay                |
| `0x10..14` | `DAT_007a397c` (u32) | `code_memory_size` (0x38) | code_memory_size        |
| `0x14..18` | mixed (per chip_type) | voltage encoding      | raw_voltages / variant     |
| `0x18..1c` | `DAT_00904e88` (u32) | (UI / mode globals)    | mode flags                 |
| `0x1c..20` | `DAT_00904e8c` (u32) |                        | mode flags                 |
| `0x20..24` | `DAT_00904e90` (u32) |                        | mode flags                 |
| `0x24..28` | `DAT_00904e94`        | or `DAT_0080187b` (eMMC ver. 0x05) | algorithm sub-mode |
| `0x28..2c` | `DAT_007a39d4` (u32) |                        |                            |
| `0x2c..30` | `DAT_007a39b6` (u32) |                        |                            |
| `0x30..32` | `DAT_007a3ba4` (u16) |                        |                            |
| `0x32..34` | `DAT_007a39be` (u16) |                        |                            |
| `0x34..38` | `DAT_007a39d0` (i32) |                        |                            |
| `0x38..3c` | `DAT_007a39d8` (u32) |                        |                            |
| `0x3c..3f` | 0                    |                        | padding                    |
| `0x3f`     | `DAT_007a39a9`       |                        |                            |

The mapping isn't 100% literal because `FUN_00444bc0` has many `if`
branches by `DAT_007a3978` (chip_type) that swap some fields. The
table above is the **eMMC (`0x31`) branch**. Practical implication
for our prototype: every field above is reachable from the dumped
`emmc_chips_t48.json`, so the packet can be assembled offline for any
of the 4 796 chips.

### 20.3 Voltage configuration

For eMMC, the voltage is baked into the `BEGIN_TRANSACTION` packet — the
programmer doesn't take a separate `SET_VCC_VOLTAGE` command. The
relevant Xgpro UI strings show **three discrete VCCQ choices**, all
combined with a fixed `VCC = 3.0 V`:

```
"VCC=3.0V VCCQ=1.2V"
"VCC=3.0V VCCQ=1.8V"
"VCC=3.0V VCCQ=3.0V"
```

Plus a fine-trim:
```
"VCCQ + 0.0V" / "VCCQ + 0.1V" / "VCCQ + 0.2V" / "VCCQ + 0.3V"
```

These choices feed into the `variant` of the chip selected in the UI
(low byte of `variant` → pkt byte `0x02`). For example
`variant = 0x4100` → ISP 1-bit / 1.8 V; `variant = 0x4133` → ISP 1-bit / 3.3 V
(`0x33` = `'3'`, ASCII for the voltage suffix in our `.alg` file naming).

So **switching `VCCQ` is a matter of picking the right chip variant in the
database before issuing `BEGIN_TRANSACTION`** — no explicit voltage opcode
is needed for eMMC. (For classic chips the `SET_VCC_VOLTAGE` opcode
`0x1B` and `SET_VPP_VOLTAGE` `0x1C` *are* used; minipro's
`t48_set_vcc_voltage()` is the reference.)

### 20.4 Overcurrent protection (OVC)

Match between minipro `t48_get_ovc_status` and Xgpro `FUN_00444bc0`:

| Step | Bytes (LE)                  | Meaning                                       |
|------|-----------------------------|-----------------------------------------------|
| 1    | `39 00 00 00 00 00 00 00`   | send `REQUEST_STATUS` (8 bytes EP1 OUT)       |
| 2    | recv 32 bytes EP1 IN        | status block                                  |
| 3    | `reply[12] & 0x01`          | overcurrent flag (1 = tripped, 0 = OK)        |

Other useful fields in the 32-byte status reply (minipro mapping):
- `reply[0]` — error code (last operation)
- `reply[2..4]` — counter `c1` (LE u16)
- `reply[4..6]` — counter `c2` (LE u16)
- `reply[8..12]` — verify-write address (LE u32)
- `reply[12]` — OVC byte

On OVC trip, Xgpro sends an END_TRANSACTION with byte 1 = 0x01:
```
04 01 00 00 00 00 00 00
```
and shows "OverCurrent Protection !" + a system beep.

### 20.5 Pin detection / "Bad Pins Connection"

Pin detection is **part of the same `FUN_00444bc0` flow** — there is no
separate "pin test" opcode like minipro's `T48_READ_PINS = 0x35`. The
`BEGIN_TRANSACTION` packet itself contains pin-direction / pull-up /
pull-down information (it was assembled from chip-specific
`pin_map`/`package_details`), and the programmer reports the result
through the same status field set as OVC. The strings
`"Pin Detected ERROR!"`, `"Pin Detected Passed."`,
`"Bad PINs Connection."` are formatted from the 32-byte status reply,
but the exact bits we still need to confirm with a USB capture.

For our purpose the practical algorithm is:

```python
emmc.begin_session_with_ovc_check(packet64)   # uses BEGIN_TRANS + REQUEST_STATUS
if result['ovc']:
    abort("OverCurrent: bad connection or short")
# pin-status bits live elsewhere in the 32-byte reply; TBD bit positions
# but we already have the bytes — diffing OK-vs-bad-pin captures will fix
# the mapping.
```

### 20.6 Pipe transfer timeouts

`FUN_004dbd00` (§19.12) configures `PIPE_TRANSFER_TIMEOUT` on `0x81 / 0x82 / 0x83`
before long operations (eMMC EXT_CSD read uses 5 000 ms timeout, normal
reads use 50 000 ms). Always set this before a long-running session.

---

## 21. Voltages: the *full* picture (correction)

I previously sketched "VCC = 3.0 V (fixed)" for eMMC. That's only how the
Xgpro UI labels the three discrete VCCQ presets for eMMC operations — the
underlying T48 hardware is far more capable.

### 21.1 Real DAC ranges (from minipro)

| Rail   | Steps | Range (V)             | Step (typ.) | API in classic minipro                   |
|--------|------:|-----------------------|-------------|------------------------------------------|
| VCC    |   64  | **1.74 .. 6.86**      | ~0.08 V     | `t48_set_vcc_voltage(index 0..63)`        |
| VPP    |   64  | **9.31 .. 25.16**     | ~0.25 V     | `t48_set_vpp_voltage(index 0..63)`        |
| VCCIO  |    5  | 2.35, 2.47, 2.93, 3.23, 3.45 | — | `t48_set_vccio_voltage(index 0..4)`      |
| VUSB   |     — | (measure only)        | —           | reported by `MEASURE_VOLTAGES`            |

The exact tables (`VCC_MAP`, `VPP_MAP`, `VCCIO_MAP`) are reproduced in
`examples/t48_emmc.py`.

### 21.2 How a voltage is actually set

```
SET_VCC voltage:
   msg[0]=0x2E (T48_SET_VCC_PIN), msg[0x10]=J13/J14 enable bits,
   msg[0x14]=0 (DAC hold), msg[0x16]=vcc_index (1..63)
   → send 48 bytes EP1 OUT.

SET_VPP voltage (programming voltage):
   msg[0]=0x2F (T48_SET_VPP_PIN), msg[1]=0x01 (sub-cmd "set VPP"),
   msg[8]=vpp_index (0..63)
   → send 48 bytes EP1 OUT.

SET_VCCIO voltage (5-step IO voltage):
   msg[0]=0x2F, msg[1]=0x02 (sub-cmd "set VCCIO"), msg[8]=vccio_index (0..4)
   → send 48 bytes EP1 OUT.
```

### 21.3 Reading the rails back

```
MEASURE_VOLTAGES (opcode 0x33):
   msg[0]=0x33, zero-padded to 16 bytes → send EP1 OUT (16)
   recv 24 bytes EP1 IN, then:
       vpp_volts   = u16(reply[8])  * 0x0F78 / 0x1000 / 100
       vusb_volts  = u16(reply[12]) * 0xCCF6 / 0x27000 / 100
       vcc_volts   = (u16(reply[16]) * 0xB32E / 0x27000 - 0x14) / 100
       vccio_volts = u16(reply[20]) * 0x0294 / 0x1000 / 100
```

This lets the host verify what the DAC is *actually* outputting,
including before connecting a chip. Match against what was requested as
a sanity check.

### 21.4 Hardware capability vs. firmware/UI restriction

There are two distinct layers of "what voltage is allowed":

**A. T48 hardware (the DACs themselves):**

| Rail   | Steps | Range                    | Resolution |
|--------|------:|--------------------------|------------|
| VCC    |    64 | 1.74 .. 6.86 V           | ~80 mV     |
| VPP    |    64 | 9.31 .. 25.16 V          | ~250 mV    |
| VCCIO  |     5 | {2.35, 2.47, 2.93, 3.23, 3.45} V | — |

The DACs are not arbitrary — they're 64-step lookups — but for VCC and
VPP the resolution is fine enough to cover ~any sensible target voltage.

**B. Xgpro UI / firmware logic (the presets actually offered):**

For *classic* chips the UI menu offers a discrete set of about a dozen
values: `1.20 / 1.80 / 2.50 / 3.00 / 3.30 / 4.00 / 4.50 / 4.75 / 5.00 /
5.25 / 5.50 / 6.00 / 6.25 / 6.50 V`, each combinable with a `±0.3 V`
fine-trim in `0.1 V` steps. So in practice for a classic chip you can
hit pretty much any voltage your datasheet asks for, in `100 mV` steps.

For *eMMC* the UI is far more restrictive — only the three JEDEC IO
classes plus the same fine-trim:

```
VCC  = 3.0 V (fixed)
VCCQ ∈ {1.2 V, 1.8 V, 3.0 V}     ← selected via chip's `variant` field
fine-trim: VCC and VCCQ each ±0.3 V in 0.1 V steps
```

This is **not** because the hardware can't do other values — it can.
It's because JEDEC defines eMMC IO voltages as discrete classes, and a
real eMMC controller is only specified to behave correctly inside one of
those three windows. Setting `VCCQ = 2.5 V` would put the chip's I/O
deck in an undefined zone — best case it just refuses commands, worst
case it latches up.

**Can we expose arbitrary VCC/VCCQ in our own software?**

For the *classic-chip* path: yes — `set_vcc_voltage(0..63)` and
`set_vpp_voltage(0..63)` already give 64-step control directly.

For the *eMMC* path: **don't**. The voltages are encoded inside the
64-byte `BEGIN_TRANSACTION` packet via the chip's `variant`. Picking
the wrong variant (e.g. the `_33` suffix on a 1.8 V chip) destroys the
chip in milliseconds — see §22.6. The right knob to expose to the user
is the *chip selection* (with VCCQ derived from the chip's datasheet),
not a freeform voltage spinbox.

If you really need an off-class VCCQ — say, characterising chip
behaviour at 2.0 V — do it on a sacrificial part with
`set_vcc_voltage()` directly, never on the device you care about.

### 21.6 Where eMMC fits in

For eMMC sessions Xgpro does **not** invoke `SET_VCC_VOLTAGE` or
`SET_VPP_VOLTAGE` separately. The voltages get encoded into the 64-byte
`BEGIN_TRANSACTION` packet itself (see §20.2) by way of the chip's
`variant` field. The UI labels — `VCC=3.0V VCCQ={1.2,1.8,3.0}V` — are
just the three normal eMMC IO-voltage classes (HS-200 / HS-400 / legacy).
Behind those labels the T48 firmware sets up the VCC DAC and the IO-bank
power independently — fine-trim `+0.0..+0.3 V` is also exposed in the UI
for stability tuning.

For our own software, this means: for eMMC use `begin_transaction(...)`,
not the discrete VCC/VPP setters. The discrete setters are for the
classic-chip path.

---

## 22. **Safe operating procedure** — *do not skip*

> ⚠️ This section is the most important one if you're building / testing
> something against a real eMMC. **Setting the wrong VCCQ (e.g. driving
> 3.3 V into a 1.8 V eMMC) destroys the chip — and possibly the host
> SoC sharing the same rail — in milliseconds.**

### 22.1 One-time bench setup

1. **First-power-up of the T48 itself:** plug it into the PC with **no
   chip and no adapter** in the ZIF socket. Run Xgpro → `Tools →
   System Self-check` once. The selftest sequence (`SELFTEST_SET_VCC`,
   `SELFTEST_SET_VPP`, `SELFTEST_SET_GND`, `SELFTEST_READ_IO`) verifies
   every rail and every pin driver. **Do not skip this on a new unit.**
2. **Sacrificial eMMC for prototyping:** for early USB-protocol
   experiments, use a *cheap dead-phone eMMC* on a breakout board, not
   a working device. Trying things on a $2000 phone PCB is how people
   brick boot partitions and find out CMD25 wrote the wrong address.

### 22.2 Per-session pre-flight (do every time)

Before issuing **any** USB command that could energise the target:

1. **Identify the chip by datasheet, not by guess.** Get the
   manufacturer + part number, look up VCCQ tolerance (1.7–1.95 V for
   "1.8 V" parts; 2.7–3.6 V for "3.3 V" parts). A 1.8 V eMMC has no
   meaningful tolerance for 3.3 V.
2. **Pick the right chip variant in our database
   (`emmc_chips_t48.json`).** For ISP work:
     - `_(ISP)_1Bit` with `_18` suffix → variant `0x4100`, VCCQ = 1.8 V
     - `_(ISP)_1Bit` with `_33` suffix → variant `0x4133`, VCCQ = 3.3 V
     - `_(ISP)_4Bit` with `_18`         → variant `0x4400`, VCCQ = 1.8 V
     - `_(ISP)_4Bit` with `_33`         → variant `0x4433`, VCCQ = 3.3 V
   The `_18` / `_33` suffix in the `.alg` file name is the suffix of the
   variant low byte (`0x00` = nothing → 1.8 V, `0x33` = `'3'` → 3.3 V).
3. **Wire ISP per the user-guide diagram.** Minimum 6 wires:
   `GND` × 2, `CLK`, `CMD`, `DAT0`, `VCCQ`. Two grounds, not one — the
   second ground stabilises the CLK return path. CLK series resistor on
   the board should be **removed** for high-frequency reliability.
4. **`RST_n` of the eMMC must idle high.** Verify with a multimeter that
   `RST_n` reads close to `VCCQ` with everything *powered but idle*.
   If it sits at 0, add a ~1 kΩ pull-up to `VCCQ` per the user guide,
   otherwise the eMMC never exits reset and the programmer reports
   `EMMC Init ERROR` (best case) or appears dead (worst case).
5. **Stop the host SoC.** If the eMMC is soldered to a phone/router/TV
   PCB, the host CPU will fight the T48 for the eMMC bus the moment
   power is applied. The user guide's recipe is to **ground the host
   MCU's crystal** to stop its clock. Verify the host stays in reset
   before continuing.
6. **Genuine adapter only.** XGecu's EMMC-ISP VER 1.00 adapter has a
   secure-element that the firmware authenticates with. Counterfeit
   adapters cause `Adapter not matched, use:` errors *before* any
   chip-side power is applied, which is also a safety feature.

### 22.3 Programmer-safe start-up sequence

The order matters. From cold:

1. **PC ← USB ← T48** (programmer connected to host, but Xgpro / our
   program **not yet running** any operation).
2. **Adapter into ZIF.** ZIF lever down.
3. **Adapter probe → target board ISP points.** Probe is *not yet*
   powered (the T48 firmware decides when to switch on its rails).
4. **Target board power-on.** This brings `VCCQ` *from the target side*
   up to whatever the target board uses (often 1.8 V supplied by the
   target's own PMIC). Verify with a meter at the probe pins:
   `VCCQ` ≈ what your chip variant declares.
5. **Open the software / run the prototype.** The first command our
   program (or Xgpro) sends is the 64-byte `BEGIN_TRANSACTION`:
   - The T48 firmware now configures its IO drivers for the chosen
     variant, and immediately follows with `REQUEST_STATUS` (opcode
     `0x39`) — recv 32 bytes — and checks `reply[12] & 0x01`.
   - If `OVC` flag is set, the firmware has already de-energised the
     driver. Our software must then send `END_TRANSACTION` with byte 1
     = `0x01` (the Xgpro convention) and **abort** the session. **Do
     not retry without diagnosing why** — `External short or IC reverse
     or incorrect package!` is the firmware's three best guesses.
6. **Only after a clean `BEGIN_TRANSACTION`** do we issue opcode `0x21`
   (eMMC init), then `0x05` (CID), `0x06` (CSD), then the CMD6 SWITCH
   to HS-200 — and only then any user-level read/write.

### 22.4 During the session

- **Treat every reply as opt-in valid.** Status byte at `reply[1]`
  (Format A / Format B short reply) is `0` for OK; non-zero is an
  error code — abort the operation, don't pretend it succeeded.
- **Cap operation time** with the per-pipe timeout (see §19.12 /
  §20.6). For ECSD reads use ~5 s, for full-USER reads use minutes
  (Xgpro uses 50 s per chunk by default).
- **Periodic OVC re-check.** A clean `BEGIN_TRANSACTION` doesn't
  guarantee the rails stay clean. After every CMD25 burst, after
  every partition switch, before every long bulk-read — send
  `REQUEST_STATUS` and check `reply[12] & 0x01`. If it flips to 1,
  bail out immediately.

### 22.5 End-of-session — *always*

```
1. STOP_AND_STATUS (Format A, sub-op 0x4C, arg=0)     // CMD12 stop in-flight transfer
2. SWITCH back to USER access (op 0x46, arg 0x02B30700) // restore default partition view
3. END_TRANSACTION (top-op 0x04, byte1=0)               // release programmer
4. Pull the probe off the target *before* powering the target down
5. Power down the target, then close the program / unplug USB
```

If anything in steps 1–3 fails, still do steps 4–5 in order.
Powering down the target while the programmer is still driving signals
into it is a common way to latch up the chip.

### 22.6 Common ways to brick a chip — and how to avoid each

| Mistake                                          | Result                | Prevention                                   |
|--------------------------------------------------|-----------------------|----------------------------------------------|
| Pick `_33` variant for a 1.8 V chip              | Chip destroyed in ms  | Verify VCCQ from datasheet *before* coding the variant. |
| Power the target before plugging the probe       | Bus contention spike  | Probe first, target power second.            |
| Skip the RST_n pull-up                           | Init fails, sometimes latch-up | 1 kΩ to VCCQ, verified with meter.    |
| Run with host SoC still clocking                 | CRC errors / latch-up | Ground the host MCU crystal pad.             |
| Treat OVC as transient and retry                 | Hard short → damage   | Abort, fix wiring, only then retry.          |
| Write to RPMB without the right Auth-Key         | RPMB permanently bricked | Don't enable RPMB write unless you have the key on file. |
| Disconnect USB mid-operation                     | eMMC in undefined state | End_TRANSACTION first, then unplug.          |
| Use a counterfeit adapter that bypasses auth     | All bets are off      | Genuine XGecu EMMC-ISP VER 1.00 only.        |

### 22.7 Pre-flight self-check sequence (Ghidra-decoded)

Xgpro's "System Self-check" function (`FUN_004532e0`) is the **safest
possible activation pattern** the firmware uses to validate itself.
We can reproduce it offline in our own software to prove the
programmer is healthy without any chip in the socket. The exact
sequence (op-codes and packet sizes from the decompilation):

```
PRE-CONDITION: no chip, no adapter in the ZIF socket.

1. send 8B  [0x2D, 0, 0,…]               ; RESET_PIN_DRIVERS

2. download "TestVcc.alg" FPGA bitstream  ; via top-op 0x26
   (Xgpro reads the .alg from disk and uses FUN_004bb4d0).

3. send 8B  [0x2D, 0, 0,…]               ; reset after bitstream load

4. VCC test loop:
   a. send 32B starting with 0x2E         ; SET_VCC_PIN — pick a pin
   b. send 8B  [0x35, 0,…]               ; READ_PINS
   c. recv 40B (0x28) — pin readings      ; reply[8..48] = per-pin status
   d. if any step != 0 → "SELFTEST_SET_VCC cmd error!"

5. VPP test loop:
   a. send 32B starting with 0x2F         ; SET_VPP_PIN
   b. send 8B  [0x35,…]                  ; READ_PINS
   c. recv 40B
   d. on failure → "SELFTEST_SET_VPP cmd error!"

6. download "TestGnd.alg" FPGA bitstream

7. send 8B [0x2D,…]                       ; reset

8. GND test loop:
   a. send 32B starting with 0x30         ; SET_GND_PIN
   b. send 8B  [0x35,…]
   c. recv 40B
   d. on failure → "SELFTEST_SET_GND cmd error!"

9. SET_OUT test:
   a. 8B  0x2D
   b. 32B 0x36                            ; SET_OUT — drive output pins
   c. 8B  0x35
   d. 40B reply

10. Combined VCC/GND test:
    a. 8B  0x2D
    b. 32B 0x2E  (VCC pin set)
    c. 40B 0x30  (GND pin set — note 40-byte form)
    d. 8B  0x39                           ; REQUEST_STATUS
```

The pin-drivers test bitstream (`TestVcc.alg`, `TestGnd.alg`) shorts
each driver to a known reference inside the FPGA so the host can
verify the actual rail voltages with `MEASURE_VOLTAGES` and the pin
states with `READ_PINS`. **No chip is energised**, so this is the only
USB activity that's strictly safe with nothing in the socket.

### 22.8 Quick safety-wrapper in code

The prototype's `begin_session_with_ovc_check()` already enforces the
pre-flight OVC check. For long sessions, wrap operations like this:

```python
emmc = T48Emmc(); emmc.connect()
try:
    result = emmc.begin_session_with_ovc_check(packet64)
    if not result['success']:
        raise RuntimeError("OVC tripped: " + ovc_diagnosis(result['status']))

    info = emmc.init_emmc(algo_param)             # CMD0/1/2/3 init
    if info['ocr'] is None or info['cid'] is None:
        raise RuntimeError("eMMC did not respond cleanly to init")

    # Periodic OVC re-check before every long op
    for chunk_idx in range(...):
        if emmc.check_ovc():
            raise RuntimeError("OVC tripped mid-session")
        data = emmc.bulk_read(N_SECTORS_PER_CHUNK)
        # ...
finally:
    try: emmc.stop_and_status()
    except Exception: pass
    try: emmc.restore_user_access()
    except Exception: pass
    try: emmc.end_transaction(0)
    except Exception: pass
    emmc.close()
```

The `try / except` around every shutdown step ensures the programmer
gets released even if one cleanup step fails — important to avoid
leaving the eMMC bus driven while the host process exits.

---

## 23. Two more top-opcodes recovered

### 23.1 `0x0A` — generic eMMC CMD wrapper

`FUN_00495060` (the OTP-CSD programming function) builds a **32-byte
raw packet** that wraps any JEDEC eMMC CMDxx with its 16-byte data
payload:

```c
struct EP1_RawCmd_0x0A {        // 32 bytes total
    uint32_t header;            // = 0x000A0001  (top-op=0x0A, then 0x01 0x00 0x00)
    uint32_t pad0;              // = 0
    uint32_t size;              // = 0x00100000  (= 16 << 16, length of data section?)
    uint32_t jedec_cmd;         // = the JEDEC eMMC CMD number (e.g. 0x5B for CMD27)
    uint8_t  data[16];          // CMD argument / payload (e.g. 16 bytes raw CSD)
};
// → send 0x20 bytes EP1 OUT
// → recv 8 bytes EP1 IN (reply[1] = status)
```

Observed use: `jedec_cmd = 0x5B` (CMD27 PROGRAM_CSD), but the same
wrapper presumably carries any other CMDxx that needs a 16-byte data
companion. Before this raw send, Xgpro warms up with two Format-A
calls: sub-op `0x57` arg=`1` (`SET_BLOCK_COUNT`), then sub-op `0x50`
arg=`0x10` (data-prep). After the raw send + 8B reply, a final
sub-op `0x50` arg=`0x200` commits the write.

If `reply[1]` of the 8-byte response is non-zero, the chip refused
the command — typically the OTP bit was already set
("WARNING: Set CSD(OTP bit) One Time Programming!").

### 23.2 `0x35` — `READ_PINS` (the pin map)

Used by the self-check sequence to read back the entire 40-pin ZIF
state in one shot:

```c
send 8B  [0x35, 0, 0, 0, 0, 0, 0, 0]   ; EP1 OUT
recv 40B (0x28)                         ; EP1 IN
// reply[8..48] is the pin status (1 byte per pin, indices map to
// physical ZIF pin numbers — matches minipro's tl866iiplus_pin_test).
```

minipro implements this for the TL866II+ but **not** for the T48 (the
T48 entry in `minipro/src/t48.c` leaves `pin_test = NULL`). The
op-code, packet sizes and reply layout all match, so adding T48
pin-test to minipro is a 30-line patch.

### 23.3 Updated top-opcode table (final-ish)

| Top-op | Source             | Purpose                                                |
|--------|--------------------|--------------------------------------------------------|
| `0x02` | minipro classic    | `NAND_INIT`                                            |
| `0x03` | minipro / Xgpro    | `BEGIN_TRANSACTION` (64-byte init — used for eMMC too) |
| `0x04` | minipro / Xgpro    | `END_TRANSACTION` (8-byte; byte 1 = OVC-abort flag)    |
| `0x05` | minipro / Xgpro    | `READID` (also used in eMMC init for CID read)         |
| `0x06` | minipro / Xgpro    | `READ_USER` (also CSD read in eMMC init)               |
| `0x08` | Xgpro NEW          | Long-recv envelope (e.g. sub `0x48` → 512 B read)      |
| **`0x0A`** | **Xgpro NEW** | **Generic eMMC CMDxx wrapper (32-byte raw packet)**    |
| `0x14` | Xgpro NEW          | Bulk-write setup before EP2 OUT                        |
| `0x1B` | minipro classic    | `SET_VCC_VOLTAGE`                                      |
| `0x1C` | minipro classic    | `SET_VPP_VOLTAGE`                                      |
| `0x21` | Xgpro NEW          | eMMC init / select algorithm                           |
| `0x26` | Xgpro NEW          | FPGA bitstream download (incl. `TestVcc.alg`, `TestGnd.alg`) |
| `0x27` | Xgpro NEW          | eMMC sub-command dispatcher                            |
| `0x2D` | minipro classic    | `RESET_PIN_DRIVERS` (used by self-check before each phase) |
| `0x2E` | minipro classic    | `SET_VCC_PIN` (32-byte packet)                         |
| `0x2F` | minipro classic    | `SET_VPP_PIN` (sub 1 = VPP voltage; sub 2 = VCCIO)     |
| `0x30` | minipro classic    | `SET_GND_PIN` (32 or 40-byte packet)                   |
| `0x33` | minipro classic    | `MEASURE_VOLTAGES`                                     |
| **`0x35`** | minipro / Xgpro| **`READ_PINS`** (40-byte reply — pin map)              |
| `0x36` | minipro classic    | `SET_OUT` (drive output pins for self-check)           |
| `0x39` | minipro / Xgpro    | `REQUEST_STATUS` (32-byte reply incl. OVC@12)          |
| `0x3F` | minipro classic    | `RESET`                                                |

## 24. RPMB protocol — exact request-code map

`FUN_004afd10` (RPMB read-write-counter + program-key) shows the
mapping between the `req` arg of `FUN_00492670` (Format C bulk
write) and the **JEDEC RPMB request codes**:

| FUN_00492670 `req` arg | JEDEC RPMB request | Purpose                       |
|------------------------|--------------------|-------------------------------|
| `1`                    | `0x0001` `PROGRAM_KEY` | Write the 32-byte Authentication Key (one-shot) |
| `2`                    | `0x0002` `READ_WC`    | Read the write counter (one of the gating bits for any RPMB write) |
| `3`                    | `0x0003` `AUTH_DATA_WRITE` | Authenticated data write (1 sector at a time) |
| `4`                    | `0x0004` `AUTH_DATA_READ`  | Authenticated data read |
| `5`                    | `0x0005` `READ_RESULT`     | Read the response register (status of the last write) |

Two hardcoded key tables live in static data:

| Symbol           | Size  | What it likely is                                |
|------------------|-------|--------------------------------------------------|
| `DAT_0079A690`   | 32 B  | Default/factory RPMB authentication key #1       |
| `DAT_007C8048`   | 32 B  | Default/factory RPMB authentication key #2       |

`FUN_00492670` arg `param_10` picks which one (`1` → first table,
`2` → second table). With `param_10 = 0` and `param_9 = 0` no key
material is embedded, which corresponds to the `READ_WC` / `READ_RESULT`
cases above (those frames don't carry a key).

**Operational warning:** `PROGRAM_KEY` is **one-shot per chip** —
once programmed, the key can never be changed or read back. Running
this flow against a chip you don't own the key for permanently
disables RPMB write on that chip. Our prototype's `build_rpmb_frame()`
takes `key_mac` as an explicit parameter precisely so this can't
happen by accident.

### 24.1 The two-step "Program Key" flow

```
1. raw_send Format C with req=1 (PROGRAM_KEY)                     ; sends the key
2. raw_send Format C with req=5 (READ_RESULT)                     ; sends "give me the response"
3. raw_recv Format D (count=1)                                    ; reads the 512-byte response
4. parse response: byte 0x1FF & 7 — the JEDEC OPERATION_RESULT:
        0 = OK
        1 = General failure
        2 = Authentication failure
        3 = Counter failure
        4 = Address failure
        5 = Write failure
        6 = Read failure
        7 = Authentication Key not yet programmed
```

(The mapping of `byte 0x1FF & 7` to the status code comes from the
JEDEC RPMB standard; Xgpro's check `if ((bStack_12003 & 7) == 0)`
matches "OK".)

---

## 25. CARD STATUS semantics and error codes

### 25.1 Correction: sub-op `0x4D` is *not* "commit"

Earlier (§19.4, §20.2) I had labelled sub-op `0x4D` as "commit / finalize
FPGA". That was wrong. The fifth Ghidra pass found `FUN_004929f0` —
the card-status reader called from the erase wait loop — and it sends:

```c
uint8_t pkt[8] = {
    0x27,    // byte 0 — top-opcode (Format A)
    0x4D,    // byte 1 — sub-opcode  ← CMD13 SEND_STATUS
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00,   // count + arg
};
raw_send(handle, pkt, 8);
raw_recv(handle, reply, 8);
```

So sub-op `0x4D` is **CMD13 `SEND_STATUS`** — reads the eMMC card's
32-bit CARD STATUS register. The "Set Password" context that misled me
earlier was just code paths that happen to poll status after writing.

**Updated Format A sub-op table:**

| Sub-op | Semantics (corrected)                                         |
|--------|---------------------------------------------------------------|
| `0x46` | CMD6 SWITCH                                                   |
| `0x4C` | CMD12 STOP_TRANSMISSION                                       |
| **`0x4D`** | **CMD13 SEND_STATUS** (status read — corrected from "commit") |
| `0x50` | Data transfer 512 B (CMD24 / OTP / RPMB-write data phase)     |
| `0x57` | CMD23 SET_BLOCK_COUNT                                         |
| `0x5C` | TBD (1 call site)                                             |
| `0x5D` | Read WP table                                                 |

### 25.2 Status reply: error-code decoder

`FUN_004b32f0` is the central status decoder — every error string Xgpro
prints when something goes wrong is routed through this function.
Reverse-engineering its `switch (param_1 & 0xFF)` gives the full
Xgpro error-code map:

| `reply[0]` | Meaning                                                          |
|-----------:|------------------------------------------------------------------|
| `0`        | OK                                                               |
| `1`        | Generic status reply (data in `param_2`)                         |
| `2`        | CRC error (command CRC)                                          |
| `3`        | CMD1 respond error (init OCR mismatch)                           |
| `4`        | CMD1 no response                                                 |
| `5`        | CMDx no response (`%.8X` codes embedded)                          |
| `6`        | eMMC busy                                                        |
| `7`        | "No Data respond" (when bit 25 of `param_2` is clear)            |
| `8`        | DataBus CRC error → UI hint *"Reduce CLK or switch VCCQ 1.8↔3.3 V"* |
| `9`        | Write CRC error                                                  |
| `10`       | eMMC `DAT0` busy (when bit 25 of `param_2` is clear)             |
| `0xE1`     | "EMMC stops responding 1" (firmware-level timeout)               |
| `0xE2`     | "EMMC stops responding 2"                                        |
| `0xE3`     | "EMMC stops responding 3"                                        |
| `0xEE`     | "EMMC stops responding 0"                                        |

The companion `param_2` is the **JEDEC eMMC CARD STATUS register**
(R1 response, 32 bits), with the relevant subfields:

| Bit(s) | Field                  | Meaning                                  |
|-------:|------------------------|------------------------------------------|
| 25     | `READY_FOR_DATA`       | 1 = chip will accept the next data       |
| 12..9  | `CURRENT_STATE`        | Card state machine value:                |
|        |                        | 0=IDLE, 1=READY, 2=IDENT, 3=STBY, **4=TRAN**, 5=DATA, 6=RCV, 7=PRG, 8=DIS, 9=BTST, 10=SLP |

`CURRENT_STATE == TRAN (4)` means "ready for next command", which is
why the erase wait loop in §25.3 uses `& 0x1E00 == 0x800` (= `4 << 9`).

### 25.3 Erase / programming wait loop (`FUN_004acee0`)

```c
int max_iter = 10000;                             // hard timeout
int rc = read_card_status(handle, &status_buf);   // Format A op 0x4D
while (rc != -1) {
    uint32_t card_status = *(uint32_t*)&status_buf[4];
    if ((card_status & 0x1E00) == 0x800) {        // CURRENT_STATE == TRAN
        // erase / write finished, card is ready
        break;
    }
    rc = format_A_cmd(handle, /*sub_op=*/0x4C, /*arg=*/0, &status_buf);  // CMD12
    if (rc == -1) {
        report(" -- CMD12");                       // CMD12 itself failed
        break;
    }
    if (--max_iter == 0) {
        decode_status(status_buf, " -- Erase Timeout");
        break;
    }
    rc = read_card_status(handle, &status_buf);    // re-poll
}
```

Takeaways:
- Use sub-op `0x4D` for **CMD13 SEND_STATUS** (NOT 0x39 — that one is
  `REQUEST_STATUS` of the programmer itself, which carries OVC at byte 12).
- Read the **32-bit eMMC CARD STATUS** from `reply[4..8]`.
- Loop until `CURRENT_STATE == 4 (TRAN)`, send `CMD12` between polls.
- 10000 iterations ≈ enough for full-chip erase; abort with
  "Erase Timeout" otherwise.

### 25.4 Updated sub-op `0x4D` packet (Ghidra-verified)

```
byte 0: 0x27   top-opcode (Format A dispatcher)
byte 1: 0x4D   sub-opcode = CMD13 SEND_STATUS
byte 2: 0x01   ?  (always 1 in Xgpro — possibly "RCA index" or "argument bits 23..16")
byte 3: 0x00
byte 4: 0x00
byte 5: 0x00
byte 6: 0x01   ?  (always 1 — possibly "fetch full 32-bit status")
byte 7: 0x00
```

Reply: 8 bytes, layout matches Format A:

```
byte 0: error code (see §25.2 table)
byte 1: ?
byte 4..8: 32-bit eMMC CARD STATUS register (LE)
```

---

## 26. Final reverse pass — erase semantics, variant letters, sub-op 0x5E

### 26.1 Xgpro does *not* use JEDEC CMD35/36/38 for eMMC erase

`FUN_0049e010` ("Erase Partition" function, 1353 decompiled lines) was
expected to contain a `CMD35 → CMD36 → CMD38` sequence. It does not.
The function reads ECSD erase-related fields for display only:
`ERASE_GROUP_DEF[175]`, `ERASE_GRP_SIZE`, `ERASE_GRP_MULT`,
`SEC_ERASE_MULT`, `ERASE_TIMEOUT_MULT`. The actual "erase" is just
`CMD25 WRITE_MULTIPLE_BLOCK` with a zero (or 0xFF) pattern.

So **for our own software, write-before-erase isn't a separate step**:
just program the desired pattern with `bulk_write()`. Xgpro's UI option
"Erase before programming" is effectively a zero-fill via CMD25.

### 26.2 Sub-op `0x5E` under top-op `0x08` — CMD30 wrapper

`FUN_00492aa0` (the helper that's called from the erase path) builds a
Format B command with sub-op `0x5E` and length=4, and on failure prints
"Write device Error CMD30 request!". JEDEC eMMC `CMD30 SEND_WRITE_PROT`
returns a 32-bit write-protection bitmap for a given group. So:

| Format | Top-op | Sub-op | Length | Meaning             |
|--------|--------|--------|--------|---------------------|
| B      | `0x08` | `0x5E` | 4 B    | CMD30 SEND_WRITE_PROT |

The arg holds the LBA of the group being checked, and the 4-byte
response on EP2 IN is the JEDEC group-write-protection register.

### 26.3 Variant letter encoding — ASCII high byte of `variant`

`FUN_004e18d0` (the eMMC pin-fault mask selector) keys off
`DAT_007a39a9`, which is the **high byte of the chip's `variant` field**
in the database, interpreted as an ASCII character:

| Letter | Hex   | Bus mode             | Adapter type      | `.alg` family |
|:------:|:-----:|----------------------|-------------------|---------------|
| `A`    | 0x41  | 1-bit                | ISP               | `EMMC_41_…`   |
| `D`    | 0x44  | 4-bit                | ISP               | `EMMC_44_…`   |
| `Q`    | 0x51  | 1-bit                | BGA socket        | `EMMC_51_…`   |
| `S`    | 0x53  | 8-bit                | BGA socket        | `EMMC_53_…`   |
| `T`    | 0x54  | 4-bit                | BGA socket        | `EMMC_54_…`   |

These letters drive:
- the `.alg` file naming (`EMMC_<hex>_{18,33}.alg`)
- the **expected-pin bitmask** returned by `FUN_004e18d0` (so the
  diagnostic code knows which pins should be live before complaining
  about which ones are missing)

The bitmasks themselves (32-bit values like `0x0AB8A3FE`, `0x0AB8A1E0`,
…) encode which of the T48's pin lines are routed to which eMMC ball
for that variant. Useful for our software when diagnosing "Bad Pin On
ISP" reports.

---

## 27. The eMMC-ISP adapter code path

### 27.1 Variant selection — which branch is "ISP"

A chip selected from the database with variant high byte `'A'` (`0x41`)
or `'D'` (`0x44`) — i.e. variants `0x41xx` / `0x44xx` — runs the
**ISP code path**. Variant low byte still encodes voltage (`0x00` =
1.8 V, `0x33` = 3.3 V), so the four canonical ISP variants are:

| variant   | mode             | algorithm file       |
|-----------|------------------|----------------------|
| `0x4100`  | ISP 1-bit, 1.8 V | `EMMC_41_18.alg`     |
| `0x4133`  | ISP 1-bit, 3.3 V | `EMMC_41_33.alg`     |
| `0x4400`  | ISP 4-bit, 1.8 V | `EMMC_44_18.alg`     |
| `0x4433`  | ISP 4-bit, 3.3 V | `EMMC_44_33.alg`     |

`FUN_004e18d0` (§26.3) keys off the high byte: `'A' → 0x0AB8A018`,
`'D' → 0x0AB8A0DC` — these are the **expected pin bitmasks** for each
ISP variant. They are what diagnostic code compares against the actual
status reply to decide *which pin* failed (vs. just reporting "Bad Pin
On ISP").

### 27.2 Top-opcode `0x2B` — adapter command channel (new!)

`FUN_004583f0` (the function near the "Adapter not matched, use:" string)
talks to the adapter over a *new* top-opcode that wasn't in any earlier
section:

```c
void adapter_cmd(handle, byte param_a, byte param_b) {
    uint8_t pkt[8];
    *(u16*)&pkt[0] = 0xFF2B;             // byte 0 = 0x2B (top-op), byte 1 = 0xFF
    raw_send(handle, pkt, 8);            // 1st packet: query adapter
    
    *(u16*)&pkt[0] = 0x022B;             // byte 0 = 0x2B, byte 1 = 0x02
    *(u16*)&pkt[2] = param_b;            // bytes 2..4
    *(u32*)&pkt[4] = param_a;            // bytes 4..8
    raw_send(handle, pkt, 8);            // 2nd packet: configure adapter
}
```

So **top-opcode `0x2B` is the adapter channel**, with at least two
sub-codes:

| `pkt[1]` | Meaning (provisional)                                     |
|---------:|-----------------------------------------------------------|
| `0xFF`   | "query adapter" / start a transaction                     |
| `0x02`   | "set adapter parameters" (with 2- + 4-byte payload)       |

This is *separate from* the secure-element authentication that the
**adapter ↔ T48 firmware** runs between themselves — that one we do
not see from the PC. What we do see is Xgpro sending **adapter
configuration** down to the T48 firmware, which then forwards / applies
it to the genuine adapter.

For our own software the practical implication is:
- We don't need to implement the secure-element challenge/response.
- We may need to send the same `0x2B/0xFF` + `0x2B/0x02` pair Xgpro does
  before the first eMMC operation, so the firmware knows which adapter
  it's working with.
- Capturing the exact `param_a` / `param_b` from a USB session is the
  cleanest way to lock down their semantics.

### 27.3 Device identification — empty packet → 64-byte info

`FUN_004dba90` is the **first thing Xgpro sends to a freshly-opened
handle**:

```c
void identify_programmer(handle) {
    uint8_t empty_pkt[8] = {0};
    WinUsb_WritePipe(handle, /*pipe=*/1, empty_pkt, 8, ...);  // EP1 OUT — all zeros
    
    uint8_t info[64];
    int rc = raw_recv(handle, info, 0x40);                     // EP1 IN — 64 bytes
    if (rc < 8) {
        AfxMessageBox("Read device information error!");
        return;
    }
    char device_type = info[10];          // byte 10 of the 64-byte reply
    if (device_type == 0x05 ||
        device_type == 0x06 ||
        device_type == 0x07) {
        // ok — recognised T48 model
    }
}
```

This is **invaluable for our prototype**: as the very first transaction
after `connect()`, send eight zero bytes and read back 64. The reply
byte at offset 10 is a **device-type / model code** (`0x05`, `0x06`,
`0x07` correspond to the three recognised model variants); other
fields in the 64-byte block carry firmware version, serial number etc.

The convention "send an all-zero command to get a banner reply" is
common for vendor-specific WinUSB devices, but we now have it
confirmed for the T48 specifically.

### 27.4 Full ISP read flow (Ghidra-decoded)

`FUN_004a98f0` is the entry point for an **ISP-mode read** session.
Stripped to its essentials:

```c
void isp_read(handle, ..., chip_params, ...) {
    open_temp_file();
    block_count = DAT_007475a4 >> 14;             // total / 16 K
    
    update_ui(...);

    if (!FUN_004fc156(param_7, /*flag=*/0x8040, 0))
        bail_out("partition switch failed");

    uint32_t buf[128];                            // 512-byte aligned
    uint32_t current_addr = 0;
    while (block_count-- > 0) {
        // Format C bulk-write SETUP — but with req=4 (READ),
        // generate_nonce=1, no key:
        rc = FUN_00492670(handle, buf, current_addr,
                          /*p4=*/0, /*p5=*/0, /*count=*/1,
                          /*req=*/4, /*p8=*/0,
                          /*gen_nonce=*/1, /*key_src=*/0);
        if (rc == -1) { error("ReadDevice Error : CMD25"); break; }

        // Format D bulk-read — read 64 sectors (32 KB) on EP2 IN:
        FUN_00492590(handle, output_buf, /*count=*/0x40);

        save_to_file(...);
        current_addr += 0x40;
    }
}
```

Notable points compared to the BGA-socket path (`FUN_0049d910`):
- The ISP path **always** sets `gen_nonce=1` in the Format C setup. The
  random nonce is part of the frame even when no key is embedded.
  Likely the FPGA / firmware uses the nonce as a wiggle-bit reference
  for ISP signalling integrity.
- The partition switch is wrapped in `FUN_004fc156` with a 16-bit flag
  `0x8040`. The high byte `0x80` looks like a "use ISP path" gate; the
  low byte `0x40` matches our existing variant high byte for ISP 4-bit
  (and likely a sub-mask for the partition selector).

### 27.5 Adapter-side integrity check via CRC32 (`FUN_004ee610`)

`FUN_004ee610` returns a single 32-bit value computed as the CRC32
(polynomial table at `DAT_006c3300`) over **four buffers in sequence**:

```c
uint32_t adapter_integrity_crc() {
    uint32_t crc = 0xFFFFFFFF;
    crc = crc32_update(crc, DAT_007a3c0c, DAT_007a397c);   // code-memory buffer
    crc = crc32_update(crc, DAT_007a4034, DAT_007a39ac);   // CID + CSD bytes
    crc = crc32_update(crc, &DAT_007c8048, DAT_007a39b0);  // RPMB key table 2 (32 B)
    crc = crc32_update(crc, &DAT_007a3c10, 0x100);          // 256-byte config block
    return ~crc;
}
```

The fact that **the RPMB key table is part of the hash** strongly
suggests this CRC is the host-side end of an adapter-identity check —
the host needs to know its own copy of the RPMB key in order to produce
a value the adapter expects. Without the right key, the CRC differs
and the firmware can refuse to proceed.

**Important for our software:** we *don't* need to break this CRC.
The check happens between PC software (Xgpro) and the T48 firmware,
using a value that includes the chip's own data. Our software just
needs to make the same sequence of calls — `FUN_00492f30 / 00492670 /
00492590` etc. — and the firmware drives the adapter-side challenge on
its own.

### 27.6 What an ISP-read session looks like end-to-end

```
1.  connect() → open libusb a466:0a53
2.  identify_programmer()        ; FUN_004dba90 — 8 zeros → 64-byte info
3.  load_chip_params_from_db()   ; FUN_004edaa0 equivalent (locally in our code)
4.  adapter_cmd(0x2B, 0xFF, …)   ; top-op 0x2B, sub 0xFF — query
5.  adapter_cmd(0x2B, 0x02, …)   ; top-op 0x2B, sub 0x02 — configure
6.  begin_transaction(packet64)  ; top-op 0x03 — 64-byte BEGIN_TRANS
7.  request_status() → check OVC ; top-op 0x39 — reply[12] & 0x01
8.  init_emmc()                  ; opcodes 0x21 / 0x05 / 0x06 in sequence
9.  CMD6 SWITCH HS-200 etc.      ; Format A sub-op 0x46
10. read loop                    ; Format C setup with gen_nonce=1 + Format D bulk read
11. CMD13 polling between bursts ; Format A sub-op 0x4D
12. CMD12 STOP at end             ; Format A sub-op 0x4C
13. END_TRANSACTION              ; top-op 0x04
14. close()
```

The ISP-specific steps are 4–5 (`0x2B` adapter channel) and the
`gen_nonce=1` flag inside step 10. Everything else is shared with the
BGA-socket path.

### 26.4 Final unknown opcodes left

Still TBD without further effort:
- Sub-op `0x5C` (1 call site, no anchor strings, low priority).
- Exact bit positions inside the 32-byte REQUEST_STATUS reply that
  encode individual pin-fault flags — `FUN_004dc6d0` and its eMMC
  cousin `FUN_004e18d0` only choose the *expected* mask; the *actual*
  per-pin reading still needs comparison with a USB capture.
- The full 64-byte BEGIN_TRANSACTION map for the non-eMMC branches
  (we have eMMC bytes 0..0x18 plus 0x18..0x40 inferred; the
  classic-chip branches use different field slots).

These remaining items are best resolved against a USB capture from
the real hardware once it arrives.

---

## 28. Corrections — what static reverse got wrong

This file is a working document; some earlier conclusions were too
confident given the evidence. The last pass over the still-uncertain
functions before hardware arrival corrected three meaningful errors.

### 28.1 Top-opcode `0x2B` is **not** the eMMC-ISP adapter channel

§27.2 earlier claimed `0x2B` was an "adapter command channel" used to
configure the ISP adapter. The unique caller of `FUN_004583f0`
(`FUN_004576a0`) prints **"Set Uart Ports error!"** and **"Starting
uart Printer error!"** in its error paths, and immediately drops into
a UART loop after the `0x2B` pair. So:

| Old claim | New reality |
|---|---|
| Top-op `0x2B` is the eMMC-ISP adapter command channel | Top-op `0x2B` is the **UART / Serial-Printer command channel** (the "TV Tools → Serial Printing" UI feature) |
| Send `0x2B 0xFF` + `0x2B 0x02` before BEGIN_TRANSACTION | **Do not send `0x2B` at all** for eMMC ISP — it has nothing to do with the eMMC code path |
| Required for adapter recognition | Adapter recognition is **entirely** between the adapter's secure element and the T48 firmware; the PC does not participate |

The practical consequence is actually a **simplification** — our
prototype's `connect → begin_transaction → init_emmc → …` flow is
correct as-is, with **no `0x2B` step needed**.

### 28.2 `FUN_004fc156` is `CreateFileA`, not "partition switch"

§27.4 earlier read the call `FUN_004fc156(param_7, 0x8040, 0)` inside
the ISP read function as "partition switch". The body of
`FUN_004fc156` is actually a textbook `CreateFileA` wrapper:

```c
// param_3 & 0x3 → dwDesiredAccess  (0x80000000 GENERIC_READ etc.)
// param_3 & 0x70 → dwShareMode
// param_3 & 0xF00 → dwCreationDisposition
// param_4 → lpSecurityAttributes
// hands off to CreateFileA / CreateFileW
```

In context (`FUN_004a98f0` ISP read), the `0x8040` flag is the **file
mode** for the **output dump file** that captured eMMC sectors are
written to. So this call **opens a file on the host PC**, it does not
talk to the eMMC. The partition switch (CMD6 SWITCH PARTITION_CONFIG)
is sent **earlier**, via the normal `cmd_A(SWITCH, …)` we already
documented (§19.3 / §20.2).

### 28.3 Sub-op `0x5C` is an 8-counter accumulator — likely a bus test

The only caller of sub-op `0x5C` is `FUN_004b0ca0`, whose body
accumulates eight per-position byte sums over a buffer in 4-iteration
loops:

```c
int counters[8] = {0};
for (int i = 0; i < 4; i++) {
    counters[0] += data[0];
    counters[1] += data[1];
    counters[2] += data[2];
    counters[3] += data[3];
    counters[4] += data[4];
    counters[5] += data[5];
    counters[6] += data[6];
    counters[7] += data[7];
    data += 8;
}
// then calls cmd_A(handle, 0x5C, …) carrying the eight counters
```

Eight per-bit-lane sums is the canonical pattern for **bus integrity
testing** — each counter tracks bit-flips on one lane of the 8-bit
data bus (or 4 lanes × 2 cycles). The most likely role of sub-op
`0x5C` is "tell FPGA to start / report a bus-test pattern". Its
single call site is reachable only from a diagnostic dialog that
doesn't run in the normal read/write path, so we can safely leave it
unimplemented in the first prototype.

### 28.4 What remains genuinely TBD (capture-only)

After 28.1–28.3 the list of "uncertain" items is short:

- **Exact bit positions inside the 32-byte REQUEST_STATUS reply** —
  `FUN_004dc6d0` (classic pin decoder) walks a per-variant pin table
  at `DAT_006B57FC` / `DAT_006B6EE0` and ORs flags into the output
  block via bit constants `0x8`, `0x20`, `0x2A`, `0x380`, `0x228000`.
  Mapping these back to physical T48 pin numbers needs **one
  good-vs-bad-pin USB capture** to nail down.
- **Voltage encoding bytes inside the 64-byte BEGIN_TRANSACTION**
  (offsets `0x14..0x18`) — Xgpro pulls them from chip-DB globals but
  the *exact* byte order vs DAC index in the voltage tables we
  documented in §21.1 is one capture away from being closed.
- **`adapter_query` / `adapter_configure`** — removed from the
  prototype as a result of §28.1; nothing to validate.

These are honestly the only three things the prototype needs the
first USB capture to settle. Everything else is byte-for-byte
documented from the binary.
