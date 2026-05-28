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
